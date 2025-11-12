set -e
mkdir -p artifacts
echo "Running prebuild checks" > artifacts/prebuild_checks.log

bandit -r app_secure -f json -o artifacts/bandit_pre.json || true
semgrep --config=auto app_secure --json --output artifacts/semgrep_pre.json || true
grep -R --line-number -E "SECRET|PASSWORD|PRIVATE_KEY|AWS_SECRET" app_secure > artifacts/secret_grep.txt || true

if [ -s artifacts/secret_grep.txt ]; then
  echo "Secrets found, failing prebuild" | tee -a artifacts/prebuild_checks.log
  exit 1
fi

echo "Prebuild passed" | tee -a artifacts/prebuild_checks.log
