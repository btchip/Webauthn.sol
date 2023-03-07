#//********************************************************************************************/
#//  ___           _       ___               _         _    _ _    
#// | __| _ ___ __| |_    / __|_ _ _  _ _ __| |_ ___  | |  (_) |__ 
#// | _| '_/ -_|_-< ' \  | (__| '_| || | '_ \  _/ _ \ | |__| | '_ \
#// |_||_| \___/__/_||_|  \___|_|  \_, | .__/\__\___/ |____|_|_.__/
#//                                |__/|_|                        
#///* Copyright (C) 2022 - Renaud Dubois - This file is part of FCL (Fresh CryptoLib) project */
#///* License: This software is licensed under MIT License 	 */
#///* See LICENSE file at the root folder of the project.				 */
#///* FILE: Webauthn_precompute.sage						         */
#///* 											 */
#///* 											 */
#///* DESCRIPTION: precompute a 8 dimensional table for Shamir's trick from a public key
#///* 
#//**************************************************************************************/


def Init_Curve(curve_characteristic,curve_a, curve_b,Gx, Gy, curve_Order):    
	Fp=GF(curve_characteristic); 				#Initialize Prime field of Point
	Fq=GF(curve_Order);					#Initialize Prime field of scalars
	Curve=EllipticCurve(Fp, [curve_a, curve_b]);		#Initialize Elliptic curve
	curve_Generator=Curve([Gx, Gy]);
	
	return [Curve,curve_Generator];
	
#//Curve secp256r1, aka p256	
#//curve prime field modulus
sec256p_p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
#//short weierstrass first coefficient
sec256p_a =0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
#//short weierstrass second coefficient    
sec256p_b =0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
#//generating point affine coordinates    
sec256p_gx =0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
sec256p_gy =0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
#//curve order (number of points)
sec256p_n =0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;    	

#//Init    
secp256r1, G = Init_Curve(sec256p_p, sec256p_a, sec256p_b, sec256p_gx, sec256p_gy, sec256p_n);


#//example public point from webauthn.js
Q=secp256r1([114874632398302156264159990279427641021947882640101801130664833947273521181002,32136952818958550240756825111900051564117520891182470183735244184006536587423]);
   
def Precompute_Pubkey(Q, Curve):
      Pow64_PQ=[ Q for i in range(0,16)];
      Prec=[ Curve(0) for i in range(0,256)];


      Pow64_PQ[0]=Curve([sec256p_gx, sec256p_gy]);   
      Pow64_PQ[4]=Q;
     
      for j in [1..3]:
        Pow64_PQ[j]=2^64*Pow64_PQ[j-1];
        Pow64_PQ[j+4]=2^64*Pow64_PQ[j+3];
    
      Prec[0]=Curve(0);
       
      for i in range(1,256):
        Prec[i]=Curve(0);
        for j in [0..7]:
          if( (i&(1<<j))!=0):
            (Prec[i])=(Pow64_PQ[j]+ Prec[i]);
        	
      return Prec;
     
Prec=Precompute_Pubkey(Q, secp256r1);

def print_setlength(X,n):
  l=str(hex(X))[2:];
  s=len(l);
  res="";
  for i in [1..n-s]:
    res=res+"0";
  res=res+l;  
  return res;  
 
def Print_Table( Q, Curve):
 Prec=Precompute_Pubkey(Q, Curve);
 chain="0x";
 for i in [0..255]:
   px=print_setlength( Prec[i][0], 64);
   py=print_setlength( Prec[i][1], 64);
   print("\n -- \n px=", px, "\n py=",py );
   
   chain=chain+px+py;
   
 return chain;

Webauthn_Prec=Print_Table(Q, secp256r1);


     
