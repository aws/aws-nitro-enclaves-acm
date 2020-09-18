# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM busybox

ENV HELLO="Hello from the enclave side!"

CMD ["/bin/sh", "-c", "while true; do echo \"$HELLO\"; sleep 10; done"]
