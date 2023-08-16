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
global	_bn_mul_add_words
align	16
_bn_mul_add_words:
L$_bn_mul_add_words_begin:
	push	ebp
	push	ebx
	push	esi
	push	edi
	; 
	xor	esi,esi
	mov	edi,DWORD [20+esp]
	mov	ecx,DWORD [28+esp]
	mov	ebx,DWORD [24+esp]
	and	ecx,4294967288
	mov	ebp,DWORD [32+esp]
	push	ecx
	jz	NEAR L$000maw_finish
align	16
L$001maw_loop:
	; Round 0
	mov	eax,DWORD [ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [edi]
	adc	edx,0
	mov	DWORD [edi],eax
	mov	esi,edx
	; Round 4
	mov	eax,DWORD [4+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [4+edi]
	adc	edx,0
	mov	DWORD [4+edi],eax
	mov	esi,edx
	; Round 8
	mov	eax,DWORD [8+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [8+edi]
	adc	edx,0
	mov	DWORD [8+edi],eax
	mov	esi,edx
	; Round 12
	mov	eax,DWORD [12+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [12+edi]
	adc	edx,0
	mov	DWORD [12+edi],eax
	mov	esi,edx
	; Round 16
	mov	eax,DWORD [16+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [16+edi]
	adc	edx,0
	mov	DWORD [16+edi],eax
	mov	esi,edx
	; Round 20
	mov	eax,DWORD [20+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [20+edi]
	adc	edx,0
	mov	DWORD [20+edi],eax
	mov	esi,edx
	; Round 24
	mov	eax,DWORD [24+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [24+edi]
	adc	edx,0
	mov	DWORD [24+edi],eax
	mov	esi,edx
	; Round 28
	mov	eax,DWORD [28+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [28+edi]
	adc	edx,0
	mov	DWORD [28+edi],eax
	mov	esi,edx
	; 
	sub	ecx,8
	lea	ebx,[32+ebx]
	lea	edi,[32+edi]
	jnz	NEAR L$001maw_loop
L$000maw_finish:
	mov	ecx,DWORD [32+esp]
	and	ecx,7
	jnz	NEAR L$002maw_finish2
	jmp	NEAR L$003maw_end
L$002maw_finish2:
	; Tail Round 0
	mov	eax,DWORD [ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [edi]
	adc	edx,0
	dec	ecx
	mov	DWORD [edi],eax
	mov	esi,edx
	jz	NEAR L$003maw_end
	; Tail Round 1
	mov	eax,DWORD [4+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [4+edi]
	adc	edx,0
	dec	ecx
	mov	DWORD [4+edi],eax
	mov	esi,edx
	jz	NEAR L$003maw_end
	; Tail Round 2
	mov	eax,DWORD [8+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [8+edi]
	adc	edx,0
	dec	ecx
	mov	DWORD [8+edi],eax
	mov	esi,edx
	jz	NEAR L$003maw_end
	; Tail Round 3
	mov	eax,DWORD [12+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [12+edi]
	adc	edx,0
	dec	ecx
	mov	DWORD [12+edi],eax
	mov	esi,edx
	jz	NEAR L$003maw_end
	; Tail Round 4
	mov	eax,DWORD [16+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [16+edi]
	adc	edx,0
	dec	ecx
	mov	DWORD [16+edi],eax
	mov	esi,edx
	jz	NEAR L$003maw_end
	; Tail Round 5
	mov	eax,DWORD [20+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [20+edi]
	adc	edx,0
	dec	ecx
	mov	DWORD [20+edi],eax
	mov	esi,edx
	jz	NEAR L$003maw_end
	; Tail Round 6
	mov	eax,DWORD [24+ebx]
	mul	ebp
	add	eax,esi
	adc	edx,0
	add	eax,DWORD [24+edi]
	adc	edx,0
	mov	DWORD [24+edi],eax
	mov	esi,edx
L$003maw_end:
	mov	eax,esi
	pop	ecx
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
global	_bn_mul_words
align	16
_bn_mul_words:
L$_bn_mul_words_begin:
	push	ebp
	push	ebx
	push	esi
	push	edi
	; 
	xor	esi,esi
	mov	edi,DWORD [20+esp]
	mov	ebx,DWORD [24+esp]
	mov	ebp,DWORD [28+esp]
	mov	ecx,DWORD [32+esp]
	and	ebp,4294967288
	jz	NEAR L$004mw_finish
L$005mw_loop:
	; Round 0
	mov	eax,DWORD [ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [edi],eax
	mov	esi,edx
	; Round 4
	mov	eax,DWORD [4+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [4+edi],eax
	mov	esi,edx
	; Round 8
	mov	eax,DWORD [8+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [8+edi],eax
	mov	esi,edx
	; Round 12
	mov	eax,DWORD [12+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [12+edi],eax
	mov	esi,edx
	; Round 16
	mov	eax,DWORD [16+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [16+edi],eax
	mov	esi,edx
	; Round 20
	mov	eax,DWORD [20+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [20+edi],eax
	mov	esi,edx
	; Round 24
	mov	eax,DWORD [24+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [24+edi],eax
	mov	esi,edx
	; Round 28
	mov	eax,DWORD [28+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [28+edi],eax
	mov	esi,edx
	; 
	add	ebx,32
	add	edi,32
	sub	ebp,8
	jz	NEAR L$004mw_finish
	jmp	NEAR L$005mw_loop
L$004mw_finish:
	mov	ebp,DWORD [28+esp]
	and	ebp,7
	jnz	NEAR L$006mw_finish2
	jmp	NEAR L$007mw_end
L$006mw_finish2:
	; Tail Round 0
	mov	eax,DWORD [ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [edi],eax
	mov	esi,edx
	dec	ebp
	jz	NEAR L$007mw_end
	; Tail Round 1
	mov	eax,DWORD [4+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [4+edi],eax
	mov	esi,edx
	dec	ebp
	jz	NEAR L$007mw_end
	; Tail Round 2
	mov	eax,DWORD [8+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [8+edi],eax
	mov	esi,edx
	dec	ebp
	jz	NEAR L$007mw_end
	; Tail Round 3
	mov	eax,DWORD [12+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [12+edi],eax
	mov	esi,edx
	dec	ebp
	jz	NEAR L$007mw_end
	; Tail Round 4
	mov	eax,DWORD [16+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [16+edi],eax
	mov	esi,edx
	dec	ebp
	jz	NEAR L$007mw_end
	; Tail Round 5
	mov	eax,DWORD [20+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [20+edi],eax
	mov	esi,edx
	dec	ebp
	jz	NEAR L$007mw_end
	; Tail Round 6
	mov	eax,DWORD [24+ebx]
	mul	ecx
	add	eax,esi
	adc	edx,0
	mov	DWORD [24+edi],eax
	mov	esi,edx
L$007mw_end:
	mov	eax,esi
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
global	_bn_sqr_words
align	16
_bn_sqr_words:
L$_bn_sqr_words_begin:
	push	ebp
	push	ebx
	push	esi
	push	edi
	; 
	mov	esi,DWORD [20+esp]
	mov	edi,DWORD [24+esp]
	mov	ebx,DWORD [28+esp]
	and	ebx,4294967288
	jz	NEAR L$008sw_finish
L$009sw_loop:
	; Round 0
	mov	eax,DWORD [edi]
	mul	eax
	mov	DWORD [esi],eax
	mov	DWORD [4+esi],edx
	; Round 4
	mov	eax,DWORD [4+edi]
	mul	eax
	mov	DWORD [8+esi],eax
	mov	DWORD [12+esi],edx
	; Round 8
	mov	eax,DWORD [8+edi]
	mul	eax
	mov	DWORD [16+esi],eax
	mov	DWORD [20+esi],edx
	; Round 12
	mov	eax,DWORD [12+edi]
	mul	eax
	mov	DWORD [24+esi],eax
	mov	DWORD [28+esi],edx
	; Round 16
	mov	eax,DWORD [16+edi]
	mul	eax
	mov	DWORD [32+esi],eax
	mov	DWORD [36+esi],edx
	; Round 20
	mov	eax,DWORD [20+edi]
	mul	eax
	mov	DWORD [40+esi],eax
	mov	DWORD [44+esi],edx
	; Round 24
	mov	eax,DWORD [24+edi]
	mul	eax
	mov	DWORD [48+esi],eax
	mov	DWORD [52+esi],edx
	; Round 28
	mov	eax,DWORD [28+edi]
	mul	eax
	mov	DWORD [56+esi],eax
	mov	DWORD [60+esi],edx
	; 
	add	edi,32
	add	esi,64
	sub	ebx,8
	jnz	NEAR L$009sw_loop
L$008sw_finish:
	mov	ebx,DWORD [28+esp]
	and	ebx,7
	jz	NEAR L$010sw_end
	; Tail Round 0
	mov	eax,DWORD [edi]
	mul	eax
	mov	DWORD [esi],eax
	dec	ebx
	mov	DWORD [4+esi],edx
	jz	NEAR L$010sw_end
	; Tail Round 1
	mov	eax,DWORD [4+edi]
	mul	eax
	mov	DWORD [8+esi],eax
	dec	ebx
	mov	DWORD [12+esi],edx
	jz	NEAR L$010sw_end
	; Tail Round 2
	mov	eax,DWORD [8+edi]
	mul	eax
	mov	DWORD [16+esi],eax
	dec	ebx
	mov	DWORD [20+esi],edx
	jz	NEAR L$010sw_end
	; Tail Round 3
	mov	eax,DWORD [12+edi]
	mul	eax
	mov	DWORD [24+esi],eax
	dec	ebx
	mov	DWORD [28+esi],edx
	jz	NEAR L$010sw_end
	; Tail Round 4
	mov	eax,DWORD [16+edi]
	mul	eax
	mov	DWORD [32+esi],eax
	dec	ebx
	mov	DWORD [36+esi],edx
	jz	NEAR L$010sw_end
	; Tail Round 5
	mov	eax,DWORD [20+edi]
	mul	eax
	mov	DWORD [40+esi],eax
	dec	ebx
	mov	DWORD [44+esi],edx
	jz	NEAR L$010sw_end
	; Tail Round 6
	mov	eax,DWORD [24+edi]
	mul	eax
	mov	DWORD [48+esi],eax
	mov	DWORD [52+esi],edx
L$010sw_end:
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
global	_bn_div_words
align	16
_bn_div_words:
L$_bn_div_words_begin:
	mov	edx,DWORD [4+esp]
	mov	eax,DWORD [8+esp]
	mov	ecx,DWORD [12+esp]
	div	ecx
	ret
global	_bn_add_words
align	16
_bn_add_words:
L$_bn_add_words_begin:
	push	ebp
	push	ebx
	push	esi
	push	edi
	; 
	mov	ebx,DWORD [20+esp]
	mov	esi,DWORD [24+esp]
	mov	edi,DWORD [28+esp]
	mov	ebp,DWORD [32+esp]
	xor	eax,eax
	and	ebp,4294967288
	jz	NEAR L$011aw_finish
L$012aw_loop:
	; Round 0
	mov	ecx,DWORD [esi]
	mov	edx,DWORD [edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [ebx],ecx
	; Round 1
	mov	ecx,DWORD [4+esi]
	mov	edx,DWORD [4+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [4+ebx],ecx
	; Round 2
	mov	ecx,DWORD [8+esi]
	mov	edx,DWORD [8+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [8+ebx],ecx
	; Round 3
	mov	ecx,DWORD [12+esi]
	mov	edx,DWORD [12+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [12+ebx],ecx
	; Round 4
	mov	ecx,DWORD [16+esi]
	mov	edx,DWORD [16+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [16+ebx],ecx
	; Round 5
	mov	ecx,DWORD [20+esi]
	mov	edx,DWORD [20+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [20+ebx],ecx
	; Round 6
	mov	ecx,DWORD [24+esi]
	mov	edx,DWORD [24+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [24+ebx],ecx
	; Round 7
	mov	ecx,DWORD [28+esi]
	mov	edx,DWORD [28+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [28+ebx],ecx
	; 
	add	esi,32
	add	edi,32
	add	ebx,32
	sub	ebp,8
	jnz	NEAR L$012aw_loop
L$011aw_finish:
	mov	ebp,DWORD [32+esp]
	and	ebp,7
	jz	NEAR L$013aw_end
	; Tail Round 0
	mov	ecx,DWORD [esi]
	mov	edx,DWORD [edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [ebx],ecx
	jz	NEAR L$013aw_end
	; Tail Round 1
	mov	ecx,DWORD [4+esi]
	mov	edx,DWORD [4+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [4+ebx],ecx
	jz	NEAR L$013aw_end
	; Tail Round 2
	mov	ecx,DWORD [8+esi]
	mov	edx,DWORD [8+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [8+ebx],ecx
	jz	NEAR L$013aw_end
	; Tail Round 3
	mov	ecx,DWORD [12+esi]
	mov	edx,DWORD [12+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [12+ebx],ecx
	jz	NEAR L$013aw_end
	; Tail Round 4
	mov	ecx,DWORD [16+esi]
	mov	edx,DWORD [16+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [16+ebx],ecx
	jz	NEAR L$013aw_end
	; Tail Round 5
	mov	ecx,DWORD [20+esi]
	mov	edx,DWORD [20+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [20+ebx],ecx
	jz	NEAR L$013aw_end
	; Tail Round 6
	mov	ecx,DWORD [24+esi]
	mov	edx,DWORD [24+edi]
	add	ecx,eax
	mov	eax,0
	adc	eax,eax
	add	ecx,edx
	adc	eax,0
	mov	DWORD [24+ebx],ecx
L$013aw_end:
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
global	_bn_sub_words
align	16
_bn_sub_words:
L$_bn_sub_words_begin:
	push	ebp
	push	ebx
	push	esi
	push	edi
	; 
	mov	ebx,DWORD [20+esp]
	mov	esi,DWORD [24+esp]
	mov	edi,DWORD [28+esp]
	mov	ebp,DWORD [32+esp]
	xor	eax,eax
	and	ebp,4294967288
	jz	NEAR L$014aw_finish
L$015aw_loop:
	; Round 0
	mov	ecx,DWORD [esi]
	mov	edx,DWORD [edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [ebx],ecx
	; Round 1
	mov	ecx,DWORD [4+esi]
	mov	edx,DWORD [4+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [4+ebx],ecx
	; Round 2
	mov	ecx,DWORD [8+esi]
	mov	edx,DWORD [8+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [8+ebx],ecx
	; Round 3
	mov	ecx,DWORD [12+esi]
	mov	edx,DWORD [12+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [12+ebx],ecx
	; Round 4
	mov	ecx,DWORD [16+esi]
	mov	edx,DWORD [16+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [16+ebx],ecx
	; Round 5
	mov	ecx,DWORD [20+esi]
	mov	edx,DWORD [20+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [20+ebx],ecx
	; Round 6
	mov	ecx,DWORD [24+esi]
	mov	edx,DWORD [24+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [24+ebx],ecx
	; Round 7
	mov	ecx,DWORD [28+esi]
	mov	edx,DWORD [28+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [28+ebx],ecx
	; 
	add	esi,32
	add	edi,32
	add	ebx,32
	sub	ebp,8
	jnz	NEAR L$015aw_loop
L$014aw_finish:
	mov	ebp,DWORD [32+esp]
	and	ebp,7
	jz	NEAR L$016aw_end
	; Tail Round 0
	mov	ecx,DWORD [esi]
	mov	edx,DWORD [edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [ebx],ecx
	jz	NEAR L$016aw_end
	; Tail Round 1
	mov	ecx,DWORD [4+esi]
	mov	edx,DWORD [4+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [4+ebx],ecx
	jz	NEAR L$016aw_end
	; Tail Round 2
	mov	ecx,DWORD [8+esi]
	mov	edx,DWORD [8+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [8+ebx],ecx
	jz	NEAR L$016aw_end
	; Tail Round 3
	mov	ecx,DWORD [12+esi]
	mov	edx,DWORD [12+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [12+ebx],ecx
	jz	NEAR L$016aw_end
	; Tail Round 4
	mov	ecx,DWORD [16+esi]
	mov	edx,DWORD [16+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [16+ebx],ecx
	jz	NEAR L$016aw_end
	; Tail Round 5
	mov	ecx,DWORD [20+esi]
	mov	edx,DWORD [20+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	dec	ebp
	mov	DWORD [20+ebx],ecx
	jz	NEAR L$016aw_end
	; Tail Round 6
	mov	ecx,DWORD [24+esi]
	mov	edx,DWORD [24+edi]
	sub	ecx,eax
	mov	eax,0
	adc	eax,eax
	sub	ecx,edx
	adc	eax,0
	mov	DWORD [24+ebx],ecx
L$016aw_end:
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
%else
; Work around https://bugzilla.nasm.us/show_bug.cgi?id=3392738
ret
%endif
#endif  // defined(__i386__) && defined(_WIN32)
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

