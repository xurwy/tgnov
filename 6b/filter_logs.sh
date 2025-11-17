#!/bin/bash

# Filter client2.txt to keep only lines containing tmessages, MTProto, and tgnet
grep -E "(tmessages|MTProto|tgnet)" client2.txt > filtered_client2.txt

echo "Filtered logs saved to filtered_client2.txt"
echo "Lines kept: $(wc -l < filtered_client2.txt)"
echo "Original lines: $(wc -l < client2.txt)"