.686p
.model flat, stdcall
option casemap:none
option prologue:none
option epilogue:none
.code



get_frdepackersize proc export
    mov eax, unpacker_end - KKrunchyDepacker
    ret
get_frdepackersize endp

get_frdepackerptr proc export
    mov eax, KKrunchyDepacker
    ret
get_frdepackerptr endp

KKrunchyDepacker:
depacker proc
sub esp,0C9Ch
mov edx,dword ptr [esp+0CA4h]
xor ecx,ecx
push ebx
push ebp
push esi
mov esi,dword ptr [esp+0CACh]
push edi
push 4h
mov dword ptr [esp+14h],esi
pop edi

LABEL_0x00F12678:
movzx eax,byte ptr [edx]
shl ecx,8h
or ecx,eax
inc edx
sub edi,1h
jne LABEL_0x00F12678 ; => 0x00F12678
or dword ptr [esp+1Ch],0FFFFFFFFh
lea edi,dword ptr [esp+20h]
mov ebp,dword ptr [esp+10h]
mov eax,400h
mov dword ptr [esp+18h],ecx
mov ecx,323h
mov dword ptr [esp+14h],edx
rep stosd 
xor eax,eax
xor edi,edi

LABEL_0x00F126AB:
sub eax,0h
je LABEL_0x00F12749 ; => 0x00F12749
sub eax,1h
jne LABEL_0x00F12761 ; => 0x00F12761
xor ebx,ebx
test edi,edi
jne LABEL_0x00F126D5 ; => 0x00F126D5
push 5h
push 2h
lea eax,dword ptr [esp+1Ch]
push eax
call DecodeBit ; => 0x00F12548 - outside range
test al,al
jne LABEL_0x00F12722 ; => 0x00F12722

LABEL_0x00F126D5:
push 123h
lea eax,dword ptr [esp+18h]
push eax
call DecodeGamma ; => 0x00F125CC - outside range
mov edi,eax
test edi,edi
je LABEL_0x00F12776 ; => 0x00F12776
push 5h
push 10h
push 3h
pop eax
push 13h
pop ecx
cmp edi,2h
cmovne eax,ecx
push eax
lea eax,dword ptr [esp+20h]
push eax
call DecodeTree ; => 0x00F12622 - outside range
shl edi,4h
xor ebx,ebx
lea ebp,dword ptr [eax-1Fh]
add ebp,edi
cmp ebp,800h
setge bl
cmp ebp,60h
jl LABEL_0x00F12722 ; => 0x00F12722
inc ebx

LABEL_0x00F12722:
push 223h
lea eax,dword ptr [esp+18h]
xor edi,edi
push eax
inc edi
call DecodeGamma ; => 0x00F125CC - outside range
add ebx,eax
je LABEL_0x00F12761 ; => 0x00F12761
mov ecx,esi
sub ecx,ebp

LABEL_0x00F1273C:
mov al,byte ptr [ecx]
mov byte ptr [esi],al
inc esi
inc ecx
sub ebx,1h
jne LABEL_0x00F1273C ; => 0x00F1273C
jmp LABEL_0x00F12761 ; => 0x00F12761

LABEL_0x00F12749:
push 4h
push 100h
push 23h
lea eax,dword ptr [esp+20h]
push eax
call DecodeTree ; => 0x00F12622 - outside range
mov byte ptr [esi],al
inc esi
xor edi,edi

LABEL_0x00F12761:
push 5h
push edi
lea eax,dword ptr [esp+1Ch]
push eax
call DecodeBit ; => 0x00F12548 - outside range
movsx eax,al
jmp LABEL_0x00F126AB ; => 0x00F126AB

LABEL_0x00F12776:
sub esi,dword ptr [esp+10h]
pop edi
mov eax,esi
pop esi
pop ebp
pop ebx
add esp,0C9Ch
ret 8h
DecodeBit:
push ebx
push esi
mov esi,dword ptr [esp+10h]
push edi
mov edi,dword ptr [esp+10h]
mov edx,dword ptr [edi+8h]
mov eax,edx
mov ecx,dword ptr [edi+4h]
shr eax,0Bh
imul eax,dword ptr [edi+esi*4h+0Ch]
cmp ecx,eax
jae LABEL_0x00F12581 ; => 0x00F12581
mov ecx,dword ptr [esp+18h]
mov dword ptr [edi+8h],eax
mov eax,800h
sub eax,dword ptr [edi+esi*4h+0Ch]
shr eax,cl
add dword ptr [edi+esi*4h+0Ch],eax
xor bl,bl
jmp LABEL_0x00F1259F ; => 0x00F1259F

LABEL_0x00F12581:
sub ecx,eax
sub edx,eax
mov dword ptr [edi+4h],ecx
mov bl,1h
mov ecx,dword ptr [esp+18h]
mov dword ptr [edi+8h],edx
mov edx,dword ptr [edi+esi*4h+0Ch]
mov eax,edx
shr eax,cl
sub edx,eax
mov dword ptr [edi+esi*4h+0Ch],edx

LABEL_0x00F1259F:
mov eax,dword ptr [edi+8h]
cmp eax,1000000h
jae LABEL_0x00F125C4 ; => 0x00F125C4
mov esi,dword ptr [edi]
mov edx,dword ptr [edi+4h]
shl edx,8h
movzx ecx,byte ptr [esi]
or edx,ecx
lea ecx,dword ptr [esi+1h]
shl eax,8h
mov dword ptr [edi+4h],edx
mov dword ptr [edi],ecx
mov dword ptr [edi+8h],eax

LABEL_0x00F125C4:
pop edi
pop esi
mov al,bl
pop ebx
ret 0Ch
DecodeGamma:
push ebp
mov ebp,esp
push ecx
xor eax,eax
inc eax
push ebx
mov dword ptr [ebp-4h],eax
mov bh,al

LABEL_0x00F125D9:
push 5h
movzx eax,bh
add eax,dword ptr [ebp+0Ch]
push eax
push dword ptr [ebp+8h]
call DecodeBit ; => 0x00F12548 - outside range
mov bl,al
add bh,bh
add bl,bh
push 5h
movzx eax,bl
add eax,dword ptr [ebp+0Ch]
push eax
push dword ptr [ebp+8h]
call DecodeBit ; => 0x00F12548 - outside range
mov ecx,dword ptr [ebp-4h]
add bl,bl
movsx eax,al
lea ecx,dword ptr [eax+ecx*2h]
mov bh,cl
mov dword ptr [ebp-4h],ecx
and bh,1h
add bh,bl
test bh,2h
jne LABEL_0x00F125D9 ; => 0x00F125D9
mov eax,ecx
pop ebx
leave 
ret 8h
DecodeTree:
push ebp
mov ebp,esp
push esi
xor esi,esi
inc esi
cmp dword ptr [ebp+10h],esi
jle LABEL_0x00F1264D ; => 0x00F1264D
push edi
mov edi,dword ptr [ebp+0Ch]

LABEL_0x00F12632:
push dword ptr [ebp+14h]
lea eax,dword ptr [esi+edi]
push eax
push dword ptr [ebp+8h]
call DecodeBit ; => 0x00F12548 - outside range
movsx ecx,al
lea esi,dword ptr [ecx+esi*2h]
cmp esi,dword ptr [ebp+10h]
jl LABEL_0x00F12632 ; => 0x00F12632
pop edi

LABEL_0x00F1264D:
sub esi,dword ptr [ebp+10h]
mov eax,esi
pop esi
pop ebp
ret 10h
depacker endp
unpacker_end:
end

