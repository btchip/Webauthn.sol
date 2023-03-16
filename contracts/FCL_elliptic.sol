//********************************************************************************************/
//  ___           _       ___               _         _    _ _    
// | __| _ ___ __| |_    / __|_ _ _  _ _ __| |_ ___  | |  (_) |__ 
// | _| '_/ -_|_-< ' \  | (__| '_| || | '_ \  _/ _ \ | |__| | '_ \
// |_||_| \___/__/_||_|  \___|_|  \_, | .__/\__\___/ |____|_|_.__/
//                                |__/|_|                        
///* Copyright (C) 2022 - Renaud Dubois - This file is part of FCL (Fresh CryptoLib) project 
///* License: This software is licensed under MIT License 	 
///* This Code may be reused including license and copyright notice. 	 
///* See LICENSE file at the root folder of the project.				 
///* FILE: FCL_elliptic.sol						         
///* 											 
///* 											 
///* DESCRIPTION: modified XYZZ system coordinates for EVM elliptic point multiplication
///*  optimization
///* 
//**************************************************************************************/
//* WARNING: this code SHALL not be used for non prime order curves for security reasons.
// Code is optimized for a=-3 only curves with prime order, constant like -1, -2 shall be replaced
// if ever used for other curve than sec256R1
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

//import "hardhat/console.sol";

library FCL_Elliptic_ZZ {
    // Set parameters for curve sec256r1.
    
    //curve prime field modulus
    uint constant p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    //short weierstrass first coefficient
    uint constant a =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    //short weierstrass second coefficient    
    uint constant b =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    //generating point affine coordinates    
    uint constant gx =
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint constant gy =
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    //curve order (number of points)
    uint constant n =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;    
    /* -2 mod p constant, used to speed up inversion and doubling (avoid negation)*/
    uint constant minus_2 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD;
    /* -2 mod n constant, used to speed up inversion*/
    uint constant minus_2modn = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F; 
       
    uint constant minus_1=      0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    
    /**
    /* inversion mod n via a^(n-2), use of precompiled using little Fermat theorem*/
    function FCL_nModInv(uint256 u) public  returns (uint256 result) {
        uint[6] memory pointer;
        assembly {
            
            // Define length of base, exponent and modulus. 0x20 == 32 bytes
            mstore(pointer, 0x20)
            mstore(add(pointer, 0x20), 0x20)
            mstore(add(pointer, 0x40), 0x20)
            // Define variables base, exponent and modulus
            mstore(add(pointer, 0x60), u)
            mstore(add(pointer, 0x80), minus_2modn)
            mstore(add(pointer, 0xa0), n)
          
            // Call the precompiled contract 0x05 = ModExp
            if iszero(call(not(0), 0x05, 0, pointer, 0xc0, pointer, 0x20)) {
                revert(0, 0)
            }
            result:=mload(pointer)
        }
       
    }
     /**
    /* @dev inversion mod nusing little Fermat theorem via a^(n-2), use of precompiled*/
    function FCL_pModInv(uint256 u) public  returns (uint256 result) {
        uint[6] memory pointer;
        assembly {  
            // Define length of base, exponent and modulus. 0x20 == 32 bytes
            mstore(pointer, 0x20)
            mstore(add(pointer, 0x20), 0x20)
            mstore(add(pointer, 0x40), 0x20)
            // Define variables base, exponent and modulus
            mstore(add(pointer, 0x60), u)
            mstore(add(pointer, 0x80), minus_2)
            mstore(add(pointer, 0xa0), p)
          
            // Call the precompiled contract 0x05 = ModExp
            if iszero(call(not(0), 0x05, 0, pointer, 0xc0, pointer, 0x20)) {
                revert(0, 0)
            }
            result:=mload(pointer)
        }
    }
    
    /**
    /* @dev Convert from affine rep to XYZZ rep*/
    function ecAff_SetZZ(
        uint x0,
        uint y0
    ) internal pure returns (uint[4] memory P) {
        unchecked {
            P[2] = 1; //ZZ
            P[3] = 1; //ZZZ
            P[0] = x0;
            P[1] = y0;
        }
    }
    
    /**
    /* @dev Convert from XYZZ rep to affine rep*/ 
    /*    https://hyperelliptic.org/EFD/g1p/auto-shortw-xyzz-3.html#addition-add-2008-s*/
    function ecZZ_SetAff( uint x,
        uint y,
        uint zz,
        uint zzz) internal  returns (uint x1, uint y1)
    {
      uint zzzInv = FCL_pModInv(zzz); //1/zzz
      y1=mulmod(y,zzzInv,p);//Y/zzz
      uint b=mulmod(zz, zzzInv,p); //1/z
      zzzInv= mulmod(b,b,p); //1/zz
      x1=mulmod(x,zzzInv,p);//X/zz
    }
    
 
    
    /**
    /* @dev Sutherland2008 doubling*/
    /* The "dbl-2008-s-1" doubling formulas */
    function ecZZ_Dbl(
    	uint x,
        uint y,
        uint zz,
        uint zzz
    ) internal pure returns (uint P0, uint P1,uint P2,uint P3)
    {
     unchecked{
     assembly{
      P0:=mulmod(2, y, p) //U = 2*Y1
      P2:=mulmod(P0,P0,p)  // V=U^2
      P3:=mulmod(x, P2,p)// S = X1*V
      P1:=mulmod(P0, P2,p) // W=UV
      P2:=mulmod(P2, zz, p) //zz3=V*ZZ1
      zz:=mulmod(3, mulmod(addmod(x,sub(p,zz),p), addmod(x,zz,p),p) ,p) //M=3*(X1-ZZ1)*(X1+ZZ1), use zz to reduce RAM usage
      P0:=addmod(mulmod(zz,zz,p), mulmod(minus_2, P3,p),p) //X3=M^2-2S
      x:=mulmod(zz,addmod(P3, sub(p,P0),p),p)//M(S-X3)
      P3:=mulmod(P1,zzz,p)//zzz3=W*zzz1
      P1:=addmod(x, sub(p, mulmod(P1, y,p)),p )//Y3= M(S-X3)-W*Y1
      }
     }
     return (P0, P1, P2, P3);
    }
    
     /**
     * @dev Sutherland2008 add a ZZ point with a normalized point and greedy formulae
     * warning: assume that P1(x1,y1)!=P2(x2,y2), true in multiplication loop with prime order (cofactor 1)
     */
     
    //tbd: return -x1 and -Y1 in double to avoid two substractions
    function ecZZ_AddN(
    	uint x1,
        uint y1,
        uint zz1,
        uint zzz1,
        uint x2,
        uint y2) internal pure returns (uint P0, uint P1,uint P2,uint P3)
     {
       unchecked{
      if(y1==0){
       return (x2,y2,1,1);
      }
  
       assembly{
      y1:=sub(p, y1)
      y2:=addmod(mulmod(y2, zzz1,p),y1,p)  
      x2:=addmod(mulmod(x2, zz1,p),sub(p,x1),p)  
      P0:=mulmod(x2, x2, p)//PP = P^2
      P1:=mulmod(P0,x2,p)//PPP = P*PP
      P2:=mulmod(zz1,P0,p) ////ZZ3 = ZZ1*PP
      P3:= mulmod(zzz1,P1,p) ////ZZZ3 = ZZZ1*PPP
      zz1:=mulmod(x1, P0, p)//Q = X1*PP
      P0:=addmod(addmod(mulmod(y2,y2, p), sub(p,P1),p ), mulmod(minus_2, zz1,p) ,p )//R^2-PPP-2*Q
      P1:=addmod(mulmod(addmod(zz1, sub(p,P0),p), y2, p), mulmod(y1, P1,p),p)//R*(Q-X3)
     }
    //end assembly
      }//end unchecked
      return (P0, P1, P2, P3);
     }
       
     /**
     * @dev Return the zero curve in XYZZ coordinates.
     */
    function ecZZ_SetZero() internal pure returns (uint x, uint y, uint zz, uint zzz) {
        return (0, 0, 0, 0);
    }
     /**
     * @dev Check if point is the neutral of the curve
     */
    function ecZZ_IsZero (uint x0, uint y0, uint zz0, uint zzz0) internal pure returns (bool)
    {
     if ( (y0 == 0)  ) {
            return true;
        }
        return false;
    }
    /**
     * @dev Return the zero curve in affine coordinates. Compatible with the double formulae (no special case)
     */
    function ecAff_SetZero() internal pure returns (uint x, uint y) {
        return (0, 0);
    }

    /**
     * @dev Check if the curve is the zero curve in affine rep.
     */
   function ecAff_IsZero(uint x, uint y) internal pure returns (bool flag) {
        return (y==0);
    }

    /**
     * @dev Check if a point in affine coordinates is on the curve (reject Neutral that is indeed on the curve).
     */
    function ecAff_isOnCurve(uint x, uint y) internal pure returns (bool) {
        if (0 == x || x == p || 0 == y || y == p) {
            return false;
        }
        unchecked {
            uint LHS = mulmod(y, y, p); // y^2
            uint RHS = addmod(mulmod(mulmod(x, x, p), x, p), mulmod(x, a, p), p); // x^3+ax
                 RHS = addmod(RHS, b, p); // x^3 + a*x + b
           
            return LHS == RHS;
        }
    }
    

      /**
     * @dev Add two elliptic curve points in affine coordinates.
     */
    function ecAff_add(
        uint x0,
        uint y0,
        uint x1,
        uint y1
    ) internal returns (uint, uint) {
        uint zz0;
        uint zzz0;
        
	if(ecAff_IsZero(x0,y0)) return (x1,y1);
	if(ecAff_IsZero(x1,y1)) return (x1,y1);
	
        (x0, y0, zz0, zzz0) = ecZZ_AddN(x0, y0, 1,1, x1, y1);

        return ecZZ_SetAff(x0, y0, zz0, zzz0);
    }

     /**
     * @dev Computation of uG+vQ using Strauss-Shamir's trick, G basepoint, Q public key
     */
     function ecZZ_mulmuladd_S_asm(
        uint Q0, uint Q1,// Point G and Q stored in one memory for stack optimization
        uint scalar_u,
        uint scalar_v
    ) internal returns (uint X) {
     uint zz;
     uint zzz;
     uint Y;
     uint index=255;
     uint[6] memory T;
     uint H0;
     uint H1;   
     if(scalar_u==0 && scalar_v==0) return 0;
     
     (H0,H1 )=ecAff_add(gx,gy,Q0, Q1);
   
     while( ( ((scalar_u>>index)&1)+2*((scalar_v>>index)&1) ) ==0){
      index=index-1; 
     }
     
     zz =((scalar_u>>index)&1)+2*((scalar_v>>index)&1);
     if(zz==1){
     	 (X,Y) = (gx, gy);
     }
     if(zz==2){
	(X,Y) = (Q0, Q1);
     }
     if(zz==3){ 
  	(X,Y) = (H0, H1);
     }
     
     index=index-1;
     
     unchecked {
     
     assembly{
      zz:=1
      zzz:=1
      
        for {  index := index } gt( minus_1, index) { index := sub(index, 1) } 
      {
       
               // inlined EcZZ_Dbl
      let T1:=mulmod(2, Y, p) //U = 2*Y1, y free
      let T2:=mulmod(T1,T1,p)  // V=U^2
      let T3:=mulmod(X, T2,p)// S = X1*V
      T1:=mulmod(T1, T2,p) // W=UV
      let T4:=mulmod(3, mulmod(addmod(X,sub(p,zz),p), addmod(X,zz,p),p) ,p) //M=3*(X1-ZZ1)*(X1+ZZ1), use zz to reduce RAM usage, x free
      zzz:=mulmod(T1,zzz,p)//zzz3=W*zzz1
      zz:=mulmod(T2, zz, p) //zz3=V*ZZ1, V free
     
      X:=addmod(mulmod(T4,T4,p), mulmod(minus_2, T3,p),p) //X3=M^2-2S
      T2:=mulmod(T4,addmod(T3, sub(p, X),p),p)//M(S-X3)
      //T2:=mulmod(T4,addmod(X, sub(p, T3),p),p)//-M(S-X3)=M(X3-S)
      
      Y:= addmod(T2, sub(p, mulmod(T1, Y ,p)),p  )//Y3= M(S-X3)-W*Y1
      //Y:= addmod(mulmod(T1, Y ,p), y ,p  ) //-Y3=W*Y1-M(S-X3)=W*Y1+M(X3-S)
      //Y:= addmod(mulmod(T1, Y ,p), sub(p, T2),p  )//-Y3= W*Y1-M(S-X3)
      
    
      //value of dibit	
      T4:=add( shl(1, and(shr(index, scalar_v),1)), and(shr(index, scalar_u),1) )
      
      if eq(T4,1) {
      	T1:=gx
      	T2:=gy
      	}
      if eq(T4,2) {
        T1:=Q0
      	T2:=Q1
      }
      if eq(T4,3) {
      	 T1:=H0
      	 T2:= H1
      	 }
      if gt(T4,0){
       // inlined EcZZ_AddN
      T3:=sub(p, Y)
      //T3:=Y
      let y2:=addmod(mulmod(T2, zzz,p),T3,p)  
      T2:=addmod(mulmod(T1, zz,p),sub(p,X),p)  
      
      T4:=mulmod(T2, T2, p)//PP
      T1:=mulmod(T4,T2,p)//PPP
      T2:=mulmod(zz,T4,p) // W=UV
      zzz:= mulmod(zzz,T1,p) //zz3=V*ZZ1
      let zz1:=mulmod(X, T4, p)
      T4:=addmod(addmod(mulmod(y2,y2, p), sub(p,T1),p ), mulmod(minus_2, zz1,p) ,p )
      Y:=addmod(mulmod(addmod(zz1, sub(p,T4),p), y2, p), mulmod(T3, T1,p),p)
      zz:=T2
      X:=T4
            }
           }//end loop
        mstore(add(T, 0x60),zzz)
      //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
      //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
     // Define length of base, exponent and modulus. 0x20 == 32 bytes
      mstore(T, 0x20)
      mstore(add(T, 0x20), 0x20)
      mstore(add(T, 0x40), 0x20)
      // Define variables base, exponent and modulus
      //mstore(add(pointer, 0x60), u)
      mstore(add(T, 0x80), minus_2)
      mstore(add(T, 0xa0), p)
               
      // Call the precompiled contract 0x05 = ModExp
      if iszero(call(not(0), 0x05, 0, T, 0xc0, T, 0x20)) {
            revert(0, 0)
      }
       
      //Y:=mulmod(Y,zzz,p)//Y/zzz
      zz :=mulmod(zz, mload(T),p) //1/z
      zz:= mulmod(zz,zz,p) //1/zz
      X:=mulmod(X,zz,p)//X/zz
      } //end assembly
     }//end unchecked
     
      return X;
    }
    
       
      //8 dimensions Shamir's trick, using precomputations stored in Shamir8,  stored as Bytecode of an external
      //contract at given address dataPointer
      //(thx to Lakhdar https://github.com/Kelvyne for EVM storage explanations and tricks)
      // the external tool to generate tables from public key is in the /sage directory
    function ecZZ_mulmuladd_S8_extcode(uint scalar_u, uint scalar_v, address dataPointer) internal  returns(uint X/*, uint Y*/)
    {
      uint zz; // third and  coordinates of the point
     
      uint[6] memory T;
      zz=256;//start index
      
      unchecked{ 
      
      while(T[0]==0)
      {
      zz=zz-1;
      //tbd case of msb octobit is null
      T[0]=64*(128*((scalar_v>>zz)&1)+64*((scalar_v>>(zz-64))&1)+32*((scalar_v>>(zz-128))&1)+16*((scalar_v>>(zz-192))&1)+
               8*((scalar_u>>zz)&1)+4*((scalar_u>>(zz-64))&1)+2*((scalar_u>>(zz-128))&1)+((scalar_u>>(zz-192))&1));
      }
     assembly{
   
      extcodecopy(dataPointer, T, mload(T), 64)
      X:= mload(T)
      let Y:= mload(add(T,32))
      let zzz:=1
      zz:=1
     
      //loop over 1/4 of scalars thx to Shamir's trick over 8 points
      for { let index := 254 } gt(index, 191) { index := sub(index, 1) } 
      { 
      let ind:=index
      // inlined EcZZ_Dbl
      let y:=mulmod(2, Y, p) //U = 2*Y1, y free
      let T2:=mulmod(y,y,p)  // V=U^2
      let T3:=mulmod(X, T2,p)// S = X1*V
      let T1:=mulmod(y, T2,p) // W=UV
      let T4:=mulmod(3, mulmod(addmod(X,sub(p,zz),p), addmod(X,zz,p),p) ,p) //M=3*(X1-ZZ1)*(X1+ZZ1), use zz to reduce RAM usage, x free
      zzz:=mulmod(T1,zzz,p)//zzz3=W*zzz1
    
      X:=addmod(mulmod(T4,T4,p), mulmod(minus_2, T3,p),p) //X3=M^2-2S
      y:=mulmod(T4,addmod(T3, sub(p, X),p),p)//M(S-X3)
      Y:= addmod(y, sub(p, mulmod(T1, Y ,p)),p  )//Y3= M(S-X3)-W*Y1
      zz:=mulmod(T2, zz, p) //zz3=V*ZZ1
       
      /* compute element to access in precomputed table */
      T4:= add( shl(13, and(shr(ind, scalar_v),1)), shl(9, and(shr(ind, scalar_u),1)) )
      ind:=sub(index, 64)
      T4:=add(T4, add( shl(12, and(shr(ind, scalar_v),1)), shl(8, and(shr(ind, scalar_u),1)) ))
      ind:=sub(index, 128)
      T4:=add(T4,add( shl(11, and(shr(ind, scalar_v),1)), shl(7, and(shr(ind, scalar_u),1)) ))
      ind:=sub(index, 192)
      T4:=add(T4,add( shl(10, and(shr(ind, scalar_v),1)), shl(6, and(shr(ind, scalar_u),1)) ))
      
      mstore(T,T4)
         /* Access to precomputed table using extcodecopy hack */
      extcodecopy(dataPointer, T,mload(T), 64)
          
      // inlined EcZZ_AddN
      y:=sub(p, Y)
      let y2:=addmod(mulmod(mload(add(T,32)), zzz,p),y,p)  
      T2:=addmod(mulmod(mload(T), zz,p),sub(p,X),p)  
      T4:=mulmod(T2, T2, p)
      T1:=mulmod(T4,T2,p)
      T2:=mulmod(zz,T4,p) // W=UV
      zzz:= mulmod(zzz,T1,p) //zz3=V*ZZ1
      let zz1:=mulmod(X, T4, p)
      T4:=addmod(addmod(mulmod(y2,y2, p), sub(p,T1),p ), mulmod(minus_2, zz1,p) ,p )
      Y:=addmod(mulmod(addmod(zz1, sub(p,T4),p), y2, p), mulmod(y, T1,p),p)
      zz:=T2
      X:=T4
     }//end loop
      mstore(add(T, 0x60),zz)
        
      //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
      //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
     // Define length of base, exponent and modulus. 0x20 == 32 bytes
      mstore(T, 0x20)
      mstore(add(T, 0x20), 0x20)
      mstore(add(T, 0x40), 0x20)
      // Define variables base, exponent and modulus
      //mstore(add(pointer, 0x60), u)
      mstore(add(T, 0x80), minus_2)
      mstore(add(T, 0xa0), p)
               
      // Call the precompiled contract 0x05 = ModExp
      if iszero(call(not(0), 0x05, 0, T, 0xc0, T, 0x20)) {
            revert(0, 0)
      }
      
      zz:=mload(T)
      X:=mulmod(X,zz,p)//X/zz
       }       
      }//end unchecked
    }
            
    /**
     * @dev ECDSA verification, given , signature, and public key.
     */
    function ecdsa_verify(
        bytes32 message,
        uint[2] memory rs,
        uint[2] memory Q
    ) internal  returns (bool) {
        if (rs[0] == 0 || rs[0] >= n || rs[1] == 0) {
            return false;
        }
        
        
        if (!ecAff_isOnCurve(Q[0], Q[1])) {
            return false;
        }
  	
        uint sInv = FCL_nModInv(rs[1]);
        uint scalar_u=mulmod(uint(message), sInv, n);
        uint scalar_v= mulmod(rs[0], sInv, n);
        uint x1;
	
       x1=ecZZ_mulmuladd_S_asm(Q[0], Q[1],scalar_u, scalar_v);
       	
        assembly{
	 x1:=addmod(x1,sub(n,mload(rs)), n)
	}
	//return true; 	
        return x1 == 0;
        
       }
     
      /**
      * @dev ECDSA verification using a precomputed table of multiples of P and Q stored in contract at address Shamir8
        generation of contract bytecode for precomputations is done using sagemath code (see sage directory, WebAuthn_precompute.sage)
      */
        
      function ecdsa_precomputed_verify(
        bytes32 message,
        uint[2] memory rs,
        address Shamir8
    ) internal  returns (bool) {
     if (rs[0] == 0 || rs[0] >= n || rs[1] == 0) {
            return false;
        }
        /* Q is pushed via bytecode assumed to be correct
        if (!isOnCurve(Q[0], Q[1])) {
            return false;
        }*/
        
        uint sInv =FCL_nModInv(rs[1]);
     	uint X;
         
       //Shamir 8 dimensions	
        X=ecZZ_mulmuladd_S8_extcode(mulmod(uint(message), sInv, n), mulmod(rs[0], sInv, n), Shamir8);
      
	assembly{
	 X:=addmod(X,sub(n,mload(rs)), n)
	}
	//return true; 	
        return X == 0;
        
        }//end  ecdsa_precomputed_verify()
}//EOF


