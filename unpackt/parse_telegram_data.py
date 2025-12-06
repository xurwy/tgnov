#!/usr/bin/env python3
"""
Parse Telegram MTProto data to match TLUploadGetFile requests with TLUploadFile responses.
Extracts document IDs and byte data from matched pairs.
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class UploadGetFile:
    """Represents a TLUploadGetFile request"""
    filename: str
    msg_id: int
    file_number: int  # Extracted from filename
    document_id: Optional[int] = None  # Id from InputFileLocation

    def __str__(self):
        return f"Request: {self.filename} (MsgId: {self.msg_id}, Id: {self.document_id})"


@dataclass
class UploadFile:
    """Represents a TLUploadFile response"""
    filename: str
    req_msg_id: int
    file_number: int  # Extracted from filename
    bytes_data: Optional[str] = None  # Bytes field from the response
    offset: Optional[int] = None  # If we find offset info

    def __str__(self):
        bytes_len = len(self.bytes_data) if self.bytes_data else 0
        return f"Response: {self.filename} (ReqMsgId: {self.req_msg_id}, Bytes: {bytes_len} chars)"


@dataclass
class MatchedPair:
    """A matched request-response pair"""
    request: UploadGetFile
    response: UploadFile

    def __str__(self):
        return f"""
Matched Pair (MsgId: {self.request.msg_id}):
  Request:  {self.request.filename} (Id: {self.request.document_id})
  Response: {self.response.filename}
  Bytes: {self.response.bytes_data[:100] if self.response.bytes_data else 'None'}...
"""


def extract_file_number(filename: str) -> int:
    """Extract the file number from the filename (e.g., 215 from '215_sent_data.bin')"""
    match = re.search(r'/(\d+)_(?:sent|received)_data\.bin', filename)
    return int(match.group(1)) if match else -1


def parse_all2_file(filepath: str) -> Tuple[List[UploadGetFile], List[UploadFile]]:
    """
    Parse the all2.txt file to extract all TLUploadGetFile and TLUploadFile entries.
    Extracts the Id field from TLUploadGetFile and Bytes field from TLUploadFile.

    Returns:
        Tuple of (requests, responses)
    """
    requests: List[UploadGetFile] = []
    responses: List[UploadFile] = []

    current_file = None
    current_msg_id = None
    current_req_msg_id = None
    current_document_id = None

    in_upload_get_file = False
    in_input_file_location = False
    in_rpc_result = False
    in_upload_file = False
    in_bytes_field = False

    bytes_buffer = []

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            # Track current file being processed
            if '=== Processing:' in line:
                match = re.search(r'=== Processing: (.+\.bin) ===', line)
                if match:
                    current_file = match.group(1)
                    current_msg_id = None
                    current_req_msg_id = None
                    current_document_id = None
                    in_upload_get_file = False
                    in_input_file_location = False
                    in_rpc_result = False
                    in_upload_file = False
                    in_bytes_field = False
                    bytes_buffer = []

            # Extract MsgId (for requests)
            elif re.match(r'\s*MsgId:\s+\d+', line):
                match = re.search(r'MsgId:\s+(\d+)', line)
                if match:
                    current_msg_id = int(match.group(1))

            # Detect TLUploadGetFile (request)
            elif 'TLUploadGetFile' in line and current_file and current_msg_id:
                if '_sent_data.bin' in current_file:
                    in_upload_get_file = True
                    current_document_id = None

            # Detect InputFileLocation within TLUploadGetFile
            elif in_upload_get_file and 'InputFileLocation' in line:
                in_input_file_location = True

            # Extract Id field from InputFileLocation
            elif in_input_file_location and re.match(r'\s*Id:\s+\d+', line):
                match = re.search(r'Id:\s+(\d+)', line)
                if match:
                    current_document_id = int(match.group(1))

            # End of TLUploadGetFile structure (closing brace)
            elif in_upload_get_file and line.strip() == '}':
                # Check if this closes the main structure
                if current_document_id is not None:
                    requests.append(UploadGetFile(
                        filename=current_file,
                        msg_id=current_msg_id,
                        file_number=extract_file_number(current_file),
                        document_id=current_document_id
                    ))
                in_upload_get_file = False
                in_input_file_location = False

            # Detect TLRpcResult
            elif 'TLRpcResult' in line:
                in_rpc_result = True
                in_bytes_field = False
                bytes_buffer = []

            # Extract ReqMsgId (for responses)
            elif in_rpc_result and re.match(r'\s*ReqMsgId:\s+\d+', line):
                match = re.search(r'ReqMsgId:\s+(\d+)', line)
                if match:
                    current_req_msg_id = int(match.group(1))

            # Detect TLUploadFile (response)
            elif in_rpc_result and 'TLUploadFile' in line and current_file:
                if '_received_data.bin' in current_file and current_req_msg_id:
                    in_upload_file = True

            # Detect start of Bytes field
            elif in_upload_file and re.match(r'\s*Bytes:\s+\{', line):
                in_bytes_field = True
                # Extract bytes from this line if any
                match = re.search(r'Bytes:\s+\{(.+)', line)
                if match:
                    bytes_content = match.group(1).strip()
                    if bytes_content and bytes_content != '}':
                        bytes_buffer.append(bytes_content)

            # Collect bytes data across multiple lines
            elif in_bytes_field:
                stripped = line.strip()
                if stripped == '},':
                    # End of bytes field - convert to continuous hex stream
                    hex_stream = ''.join(bytes_buffer).replace('0x', '').replace(',', '').replace(' ', '').strip()
                    responses.append(UploadFile(
                        filename=current_file,
                        req_msg_id=current_req_msg_id,
                        file_number=extract_file_number(current_file),
                        bytes_data=hex_stream
                    ))
                    in_upload_file = False
                    in_rpc_result = False
                    bytes_buffer = []
                elif stripped:
                    bytes_buffer.append(stripped)

    return requests, responses


def match_pairs(requests: List[UploadGetFile], responses: List[UploadFile]) -> List[MatchedPair]:
    """
    Match requests with responses based on msgId == reqMsgId.
    Ensures each pair is unique - if there are duplicates, only keeps the first one.

    Returns:
        List of unique matched pairs
    """
    # Create a dictionary of responses indexed by reqMsgId (only first occurrence)
    response_map: Dict[int, UploadFile] = {}
    for r in responses:
        if r.req_msg_id not in response_map:
            response_map[r.req_msg_id] = r

    matched_pairs: List[MatchedPair] = []
    seen_msg_ids = set()

    for request in requests:
        # Only add if we haven't seen this msgId before and there's a matching response
        if request.msg_id not in seen_msg_ids and request.msg_id in response_map:
            matched_pairs.append(MatchedPair(
                request=request,
                response=response_map[request.msg_id]
            ))
            seen_msg_ids.add(request.msg_id)

    return matched_pairs


def print_statistics(requests: List[UploadGetFile], responses: List[UploadFile],
                    matched_pairs: List[MatchedPair]):
    """Print statistics about the matching"""
    print(f"\n{'='*60}")
    print(f"STATISTICS")
    print(f"{'='*60}")
    print(f"Total TLUploadGetFile requests:  {len(requests)}")
    print(f"Total TLUploadFile responses:    {len(responses)}")
    print(f"Matched pairs:                   {len(matched_pairs)}")
    print(f"Unmatched requests:              {len(requests) - len(matched_pairs)}")
    print(f"Unmatched responses:             {len(responses) - len(matched_pairs)}")
    print(f"{'='*60}\n")


def print_matched_pairs(matched_pairs: List[MatchedPair]):
    """Print matched pairs with Id and Bytes"""
    print(f"\n{'='*80}")
    print(f"MATCHED PAIRS (with Document ID and Bytes)")
    print(f"{'='*80}")

    for i, pair in enumerate(matched_pairs, 1):
        bytes_preview = pair.response.bytes_data[:200] if pair.response.bytes_data else 'None'
        print(f"\nPair {i}:")
        print(f"  MsgId:       {pair.request.msg_id}")
        print(f"  Document Id: {pair.request.document_id}")
        print(f"  Request:     {pair.request.filename}")
        print(f"  Response:    {pair.response.filename}")
        print(f"  Bytes:       {bytes_preview}...")

    print(f"\n{'='*80}\n")


def print_unmatched(requests: List[UploadGetFile], responses: List[UploadFile],
                   matched_pairs: List[MatchedPair]):
    """Print unmatched requests and responses"""
    matched_request_ids = {p.request.msg_id for p in matched_pairs}
    matched_response_ids = {p.response.req_msg_id for p in matched_pairs}

    unmatched_requests = [r for r in requests if r.msg_id not in matched_request_ids]
    unmatched_responses = [r for r in responses if r.req_msg_id not in matched_response_ids]

    if unmatched_requests:
        print(f"\n{'='*60}")
        print(f"UNMATCHED REQUESTS ({len(unmatched_requests)})")
        print(f"{'='*60}")
        for req in unmatched_requests:
            print(f"  MsgId: {req.msg_id} (Id: {req.document_id}) - {req.filename}")
        print()

    if unmatched_responses:
        print(f"\n{'='*60}")
        print(f"UNMATCHED RESPONSES ({len(unmatched_responses)})")
        print(f"{'='*60}")
        for resp in unmatched_responses:
            print(f"  ReqMsgId: {resp.req_msg_id} - {resp.filename}")
        print()


def main():
    input_file = 'all2.txt'

    print(f"Parsing {input_file}...")
    requests, responses = parse_all2_file(input_file)

    print(f"Matching pairs...")
    matched_pairs = match_pairs(requests, responses)

    # Sort by request file number for easier viewing
    matched_pairs.sort(key=lambda p: p.request.file_number)

    # Print results
    print_statistics(requests, responses, matched_pairs)
    print_matched_pairs(matched_pairs)
    print_unmatched(requests, responses, matched_pairs)

    # Save to output file
    output_file = 'telegram_data_pairs.txt'
    print(f"Saving all matched pairs to {output_file}...")
    with open(output_file, 'w') as f:
        f.write(f"Total matched pairs: {len(matched_pairs)}\n")
        f.write(f"{'='*80}\n\n")

        for i, pair in enumerate(matched_pairs, 1):
            f.write(f"Pair {i}:\n")
            f.write(f"  MsgId:       {pair.request.msg_id}\n")
            f.write(f"  Document Id: {pair.request.document_id}\n")
            f.write(f"  Request:     {pair.request.filename}\n")
            f.write(f"  Response:    {pair.response.filename}\n")
            f.write(f"  Bytes:       {pair.response.bytes_data}\n")
            f.write(f"\n")

    print(f"Done! Results saved to {output_file}")


if __name__ == '__main__':
    main()
