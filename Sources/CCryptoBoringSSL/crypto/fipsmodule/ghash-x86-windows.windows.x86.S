#define BORINGSSL_PREFIX CCryptoBoringSSL
#if defined(__i386__) && defined(_WIN32)
; This file is generated from a similarly-named Perl script in the BoringSSL
; source tree. Do not edit by hand.

%ifdef BORINGSSL_PREFIX
%include "boringssl_prefix_symbols_nasm.inc"
%endif
%ifidn __OUTPUT_FORMAT__, win32
%ifidn __OUTPUT_FORMAT__,obj
section	code	use32 class=code align=64
%elifidn __OUTPUT_FORMAT__,win32
$@feat.00 equ 1
section	.text	code align=64
%else
section	.text	code
%endif
db	71,72,65,83,72,32,102,111,114,32,120,56,54,44,32,67
db	82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112
db	112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62
db	0
%else
; Work around https://bugzilla.nasm.us/show_bug.cgi?id=3392738
ret
%endif
#endif  // defined(__i386__) && defined(_WIN32)
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

