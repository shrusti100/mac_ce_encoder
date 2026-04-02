## Overview
The program reads input from a text file named input.txt.
 
This file defines:
Total MAC PDU size
Number of MAC Control Elements (CEs) to encode
CE blocks with parameters

 ## Compilation
To compile the project, run:
gcc main.c encoder.c input_validation.c -o mac_ce
After compilation, run:
./mac_ce

## File Structure
The input file consists of:
1. Global parameters
2. Number of Control Elements
3. Repeated CE blocks
 
## 1. Global Parameters
These must appear at the top of the file.
 
## Total pdu_size
Defines the total size of the MAC PDU (in bytes)
-------------------
Total pdu_size value
-------------------
 
## num_ce
Number of Control Elements defined in the file
----------------
num_ce value
----------------
 
## 2. Control Element Blocks
Each Control Element is defined using the following structure:

<ce_name>
parameter=value
parameter=value

## 3. Supported Control Elements
Below are the supported CE types and their required parameters.
 
### SHORT_BSR
 
<short_bsr>
lcgid=value
buffer=value
 
### PHR (Power Headroom Report)
 
<phr>
ph=value
pcmax=value

### ENH_PHR (Enhanced PHR)
 
<enhanced_phr>
ph=value
pcmax=value
 
### ENH_BFR (Enhanced Beam Failure Recovery)
 
<enhanced_bfr>
ci=value
s=value
ac=value
id=value
candidate_id=value
 
### CRNTI
 
<crnti>
value=value
 
### REC_BIT_RATE
 
<rec_bit_rate>
lcid=value
bit_rate=value
ui_dl_=0 or 1
  
### EXT_BSR
 
<extended_bsr>
lcg=value
buffer=value
 
### SL_LBT
 
<sl_lbt>
value=value

### DSR
 
<dsr>
lcg=value
rt=value
buffer=value
 
## Example
 
Total pdu_size 12
num_ce 2
 
<short_bsr>
lcgid=2
buffer=12
 
<phr>
ph=23
pcmax=5
 
## Parsing Rules
 
* CE must start with < >
* Parameters use =
* Order of parameters must match expected format
 
## Error Handling
The program may produce errors if:
 
* Invalid PDU size
* Invalid num_ce
* Unknown CE name
* Missing parameters
* Extra parameters
* non-numeric values
* Values out of range
 

 
 
 
 
 