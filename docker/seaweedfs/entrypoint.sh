#!/bin/sh
set -eu

fail() {
    echo "tracebed-seaweedfs failed" >&2
    exit 1
}

for forbidden in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN TB_S3_ACCESS_KEY TB_S3_SECRET_KEY TB_S3_ERASURE_ACCESS_KEY TB_S3_ERASURE_SECRET_KEY SEAWEED_S3_SIGNING_KEY SEAWEED_S3_INIT_ACCESS_KEY SEAWEED_S3_INIT_SECRET_KEY SEAWEED_S3_RUNTIME_ACCESS_KEY SEAWEED_S3_RUNTIME_SECRET_KEY SEAWEED_S3_ERASURE_ACCESS_KEY SEAWEED_S3_ERASURE_SECRET_KEY
do
    eval "is_set=\${$forbidden+x}"
    if [ "$is_set" = x ]; then
        fail
    fi
done

read_secret() {
    env_name=$1
    expected_path=$2
    eval "path=\${$env_name-}"
    [ "$path" = "$expected_path" ] || fail
    [ -r "$path" ] || fail
    value=$(cat "$path")
    [ -n "$value" ] || fail
    case "$value" in
        *[!A-Za-z0-9._-]*) fail ;;
    esac
    printf '%s' "$value"
}

signing_key=$(read_secret SEAWEED_S3_SIGNING_KEY_FILE /run/secrets/s3_signing_key)
init_access_key=$(read_secret SEAWEED_S3_INIT_ACCESS_KEY_FILE /run/secrets/s3_init_access_key)
init_secret_key=$(read_secret SEAWEED_S3_INIT_SECRET_KEY_FILE /run/secrets/s3_init_secret_key)
runtime_access_key=$(read_secret SEAWEED_S3_RUNTIME_ACCESS_KEY_FILE /run/secrets/s3_runtime_access_key)
runtime_secret_key=$(read_secret SEAWEED_S3_RUNTIME_SECRET_KEY_FILE /run/secrets/s3_runtime_secret_key)
erasure_access_key=$(read_secret SEAWEED_S3_ERASURE_ACCESS_KEY_FILE /run/secrets/s3_erasure_access_key)
erasure_secret_key=$(read_secret SEAWEED_S3_ERASURE_SECRET_KEY_FILE /run/secrets/s3_erasure_secret_key)

config_dir=/run/tracebed-s3
config_file="$config_dir/s3.json"
umask 077
mkdir -p "$config_dir"
cat > "$config_file" <<EOF
{"signingKey":"$signing_key","identities":[
{"name":"tracebed-s3-init","credentials":[{"accessKey":"$init_access_key","secretKey":"$init_secret_key"}],"actions":["Admin","Read","List","Tagging","Write"]},
{"name":"tracebed-s3-runtime","credentials":[{"accessKey":"$runtime_access_key","secretKey":"$runtime_secret_key"}],"actions":["Read:tracebed-traces","List:tracebed-traces","Tagging:tracebed-traces","Write:tracebed-traces"]},
{"name":"tracebed-s3-erasure","credentials":[{"accessKey":"$erasure_access_key","secretKey":"$erasure_secret_key"}],"actions":["Read:tracebed-traces","List:tracebed-traces","Write:tracebed-traces"]}
]}
EOF
chmod 600 "$config_file"

exec /entrypoint.sh "$@" -s3.config="$config_file"
