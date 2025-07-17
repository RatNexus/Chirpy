#!/bin/bash

output_path="."
output_name="out"

joined="${output_path}/${output_name}"

# Run Unit tests. If they pass. -> Build the server. If succesfull. -> Run the server. 
echo -e "----- Runing unit test -----" &&

test_output=$(go test ./... 2>&1)
test_status=$?
if [ $test_status -ne 0 ]; then
  echo -e "Some tests failed.\n"
  echo "$test_output"
  echo ""
  exit 1
else
  echo "All is well."
fi

echo -e "\n----- Building into ${joined} -----" &&
go build -o $joined &&
echo -e "\n----- Running ${joined} -----\n" &&
$joined
