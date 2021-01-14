#!/bin/bash -xe
#
# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Entry point script for the CI running on an EC2 instance.
# It is responsible for:
#    1. Publishing status updates to github.
#    2. Running the tests.
#    3. Publishing the test logs in an S3 bucket.

# Set pipe fail option to capture return code after using pipe commands (e.g. tee)
set -o pipefail
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "${SCRIPTDIR}"

# S3 bucket where additional test dependencies reside
ACM_FOR_NE_REPO_S3="aws-ne-acm-deps"

# KMS Key Id associated with the account where the CodePipeline resides
KMS_KEY_ID="0522fe28-9053-44bf-b7a5-5b74cf050ba1"

# Update Github status, see:
#   https://developer.github.com/v3/repos/statuses/
function status_update() {
        curl -H "Authorization: token ${ACCESS_TOKEN}" \
                -X POST -d '{"state":"'"${STATE}"'","target_url": "'"${LOGS_URL}"'","description": "Test runner updated","context": "test_runner/ec2-instance"}'\
                https://api.github.com/repos/aws/aws-nitro-enclaves-acm/statuses/${CODEBUILD_RESOLVED_SOURCE_VERSION}
}

# Perform the %post scriptlet steps of the RPM
function install_ne_acm_files() {
	install -D -m0644 artifacts/p11ne.eif /usr/share/nitro_enclaves/p11ne/p11ne.eif
	install -D -m0644 artifacts/image-measurements.json /usr/share/nitro_enclaves/p11ne/image-measurements.json
	install -D -m0644 src/vtok_agent/service/acm.example.yaml /usr/share/nitro_enclaves/p11ne/acm.example.yaml

	install -D -m0755 build/target/release/p11ne-client /usr/bin/p11ne-client
	install -D -m0755 build/target/release/p11ne-agent /usr/bin/p11ne-agent
	install -D -m0644 src/vtok_agent/service/nitro-enclaves-acm.service /usr/lib/systemd/system/nitro-enclaves-acm.service

	install -D -m0644 src/vtok_agent/service/acm.example.yaml /etc/nitro_enclaves/acm.example.yaml

	install -D -m0644 THIRD-PARTY-LICENSES /usr/share/licenses/aws-nitro-enclaves-acm-1.0/THIRD-PARTY-LICENSES.txt

	systemctl --system daemon-reload
}

# Cleanup what the corresponding `install` phase brought in
function uninstall_ne_acm_files() {
	rm -f /usr/share/nitro_enclaves/p11ne/p11ne.eif
	rm -f /usr/share/nitro_enclaves/p11ne/image-measurements.json
	rm -f /usr/share/nitro_enclaves/p11ne/acm.example.yaml

	rm -f /usr/bin/p11ne-client
	rm -f /usr/bin/p11ne-agent
	rm -f /usr/lib/systemd/system/nitro-enclaves-acm.service

	rm -f /etc/nitro_enclaves/acm.example.yaml

	rm -f /usr/share/licenses/aws-nitro-enclaves-acm-1.0/THIRD-PARTY-LICENSES.txt
}

pwd
source build_env.txt

PR_NUMBER=$(echo "$CODEBUILD_SOURCE_VERSION" | cut -d"/" -f2)
LOGS_PATH="tests_results/${PR_NUMBER}/ci_logs_${CODEBUILD_RESOLVED_SOURCE_VERSION}.txt"
LOGS_URL="https://console.aws.amazon.com/s3/object/aws-ne-acm-ci/${LOGS_PATH}"
ACCESS_TOKEN=$(aws ssm get-parameter --name GITHUB_TOKEN --region us-east-1 | jq -r .Parameter.Value)
if [[ $ACCESS_TOKEN == "" ]];
then
        echo "Invalid ACCESS_TOKEN"
        exit 1
fi

STATE="pending"
status_update

install_ne_acm_files

set +e
./run-nitro-enclaves-acm-tests "$ACM_FOR_NE_REPO_S3" "$KMS_KEY_ID" 2>&1 | tee test_logs.out
TEST_RESULTS=$?
set -e

uninstall_ne_acm_files

aws s3 cp test_logs.out s3://aws-ne-acm-ci/${LOGS_PATH}

STATE="success"
if [[ "${TEST_RESULTS}" != "0" ]];then
        STATE="failure"
fi

status_update
