MAC Control Element Encoder
## Overview
This program reads input from a file (input.txt) and encodes MAC Control Elements (CEs) into a MAC PDU.

## The input file specifies:
Total MAC PDU size
Number of Control Elements
Control Element blocks with parameters

## Compilation & Execution
### Compile
```bash
gcc main.c encoder\encoder.c validation\input_validation.c -Iencoder -Ivalidation -o mac_ce
```
### Run
```bash
./mac_ce
```

## Unit Testing (Google Test)
### Compile Tests
```bash
g++ tests/test.cpp encoder.o input_validation.o googletest/googletest/src/gtest-all.cc googletest/googletest/src/gtest_main.cc -Iencoder -Ivalidation -Igoogletest/googletest/include -Igoogletest/googletest -pthread -o test_app.exe
```
### RunTest
```bash
./test_app      
```

## The input file:
### 1. Global Parameters
These must appear at the top of the file:

Total pdu_size <value>
num_ce <value>
Parameters

### 2. Control Element Blocks
Each Control Element must follow this structure:

<ce_name>
parameter=value
parameter=value

### 3. Supported Control Elements
### Short_bsr
<short_bsr>
lcgid=value
buffer=value

### phr
<phr>
ph=value
pcmax=value

### enhanced_phr
<enhanced_phr>
ph1=value
ph2=value
pcmax=value

### enhanced_bfr
<enhanced_bfr>
ci=value
s=value
ac=value
id=value
candidate_id=value

### crnti
<crnti>
value=value

### rec_bit_rate
<rec_bit_rate>
lcid=value
bit_rate=value
ui_dl=0 or 1

### extended_bsr
<extended_bsr>
lcg=value
buffer=value

### sl_lbt
<sl_lbt>
value=value

### dsr
<dsr>
lcg=value
rt=value
buffer=value

### Example Input
Total pdu_size 6
num_ce 1
<short_bsr>
lcgid=2
buffer=23

### Output
```bash
MAC CE : short_bsr
Subheader Size : 1 byte
Payload Size   : 1 bytes
Total CE Size  : 2 bytes (Subheader + Payload)

Encoded Bits : 00111101 01010111
Encoded Hex  : 3D 57
[SUCCESS] short_bsr Encoded

===== FINAL SUMMARY =====
Total PDU Size   : 6 bytes
Total Used Bytes : 2 bytes
Remaining Bytes  : 4 bytes

Remaining bytes filled with 00.

Final MAC Buffer:
```text
3D 57 00 00 00 00
```

## Parsing Rules
- Control Elements must start with `< >`
- Parameters must use key=value format
- Parameter order must match expected format
- Only supported CE types are allowed