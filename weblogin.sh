#!/bin/sh

rm -f cookies.tmp

while true; do
  printf 'uniqname: '
  read WL_USER

  printf 'password: '
  stty -echo
  read WL_PWD
  stty echo
  printf '\n'

  curl --config get-weblogin.curlconfig \
    -c cookies.tmp -b cookies.tmp &> /dev/null

  WEBLOGIN_RESPONSE="$(\
    curl --config post-weblogin.curlconfig -c cookies.tmp -b cookies.tmp \
    -d \
    "ref=&service=&required=&login=$WL_USER&loginX=$WL_USER&password=$WL_PWD" \
    2>/dev/null
  )"

  ERROR="$(\
    printf '%s' "$WEBLOGIN_RESPONSE" | \
    sed -n 's/^ *var error = '\''\(.*\)'\'';$/\1/p'
  )"
  if [ "$ERROR" = "Additional authentication is required." ]; then
    break
  else
    printf '%s\n' "$ERROR"
  fi
done

DUO_CONFIG="$(\
  printf '%s' "$WEBLOGIN_RESPONSE" | \
  sed -n -e '1h;2,$H;$!d;g' -e 's/.*\n *var duo_config = \({[^}]*}\).*/\1/p'
)"

HOST="$(
  printf '%s' "$DUO_CONFIG" | \
  sed -n 's/^ *'\''host'\'': '\''\(.*\)'\'',$/\1/p'
)"
SIG="$(
  printf '%s' "$DUO_CONFIG" | \
  sed -n 's/^ *'\''sig_request'\'': '\''\(.*\):APP.*'\'',$/\1/p'
)"
SIG_PT2="$(
  printf '%s' "$DUO_CONFIG" | \
  sed -n 's/^ *'\''sig_request'\'': '\''.*:APP\(.*\)'\'',$/\1/p'
)"
ENCODED_SIG="$(printf '%s' "$SIG" | sed 's/|/%7C/g')"

DUO_URL="https://$HOST/frame/web/v1/auth?tx=$SIG&parent=https%3A%2F%2Fweblogin.umich.edu%2Fcosign-bin%2Fcosign.cgi&v=2.6"

SID="$(\
  curl -i --url "$DUO_URL" --referer "$DUO_URL" -H "Origin: https://$HOST" \
    --config post-duo-auth.curlconfig -c cookies.tmp -b cookies.tmp \
    -d "tx=$ENCODED_SIG&parent=https%3A%2F%2Fweblogin.umich.edu%2Fcosign-bin%2Fcosign.cgi&java_version=&flash_version=&screen_resolution_width=617&screen_resolution_height=330&color_depth=24&is_cef_browser=false&is_ipad_os=false" \
    2> /dev/null | \
  sed -n 's/^Location: \/frame\/prompt?sid=\(.*\)$/\1/p'
)"

DUO_PROMPT_URL="https://$HOST/frame/prompt"
DUO_REFERER_URL="$DUO_PROMPT_URL?sid=$SID"


TXID="$(\
  curl --config post-duo-prompt.curlconfig -c cookies.tmp -b cookies.tmp \
    --url "$DUO_PROMPT_URL" --referer "$DUO_REFERER_URL" \
    -H "Origin: https://$HOST" \
    -d "sid=$SID&device=phone1&factor=Duo+Push&out_of_date=&days_out_of_date=&days_to_block=None" \
    2> /dev/null | \
  sed -n 's/.*"txid": "\([^"]*\)".*/\1/p'
)"

DUO_STATUS_URL="https://$HOST/frame/status"

while true; do
  sleep 2.5
  if curl --config post-duo-status.curlconfig -c cookies.tmp -b cookies.tmp \
      --url "$DUO_STATUS_URL" --referer "$DUO_REFERER_URL" \
      -H "Origin: https://$HOST" -d "sid=$SID&txid=$TXID" \
      2> /dev/null | \
      grep -e '"status_code": "allow"' > /dev/null; then
    break
  fi
done

DUO_COOKIE="$(\
  curl --config post-duo-status.curlconfig -c cookies.tmp -b cookies.tmp \
    --url "$DUO_STATUS_URL/$TXID" --referer "$DUO_REFERER_URL" \
    -H "Origin: https://$HOST" -d "sid=$SID" \
    2> /dev/null | \
  sed -n 's/.*"cookie": "\([^"]*\)".*/\1/p'
)"
ENCODED_DUO_COOKIE="$(\
  printf '%s:APP%s' "$DUO_COOKIE" "$SIG_PT2" \
  | sed 's/|/%7C/g' | sed 's/:/%3A/g'
)"

curl --config post-weblogin.curlconfig -c cookies.tmp -b cookies.tmp \
  -d "ref=&service=&required=mtoken&duo_sig_response=$ENCODED_DUO_COOKIE" \
  &>/dev/null
