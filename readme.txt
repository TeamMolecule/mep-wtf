Prototypes for functions:
	int __usercall ZeroArgs@<W4>()
	int __usercall OneArg@<W4>(__int64 a1@<X0>)
	int __usercall TwoArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>)
	int __usercall ThreeArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>)
	int __usercall FourArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>, __int64 a4@<X3>)
	int __usercall FiveArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>, __int64 a4@<X3>, __int64)
	int __usercall SixArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>, __int64 a4@<X3>, __int64)
	int __usercall SevenArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>, __int64 a4@<X3>, __int64, __int64)
	int __usercall EightArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>, __int64 a4@<X3>, __int64, __int64)
	int __usercall NineArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>, __int64 a4@<X3>, __int64, __int64, __int64)
	int __usercall TenArgs@<W4>(__int64 a1@<X0>, __int64 a2@<X1>, __int64 a3@<X2>, __int64 a4@<X3>, __int64, __int64, __int64)

Note that the args past fourth are passed on stack. We pretend that they are int64_t's, but it's actually two separate args.

Compile:
	aarch64-linux-gnu-as test.asm -o f00d_169.o -c && aarch64-linux-gnu-ld f00d_169.o -o f00d_169.elf -Ttext=0x900000
