// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title   EllipticCurve
 *
 * @author  Tilman Drerup;
 *
 * @notice  Implements elliptic curve math; Parametrized for SECP256R1.
 *
 *          Includes components of code by Andreas Olofsson, Alexander Vlasov
 *          (https://github.com/BANKEX/CurveArithmetics), and Avi Asayag
 *          (https://github.com/orbs-network/elliptic-curve-solidity)
 *
 * @dev     NOTE: To disambiguate public keys when verifying signatures, activate
 *          condition 'rs[1] > lowSmax' in validateSignature().
 */
library EllipticCurve {
    // Set parameters for curve.
    uint constant a =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    uint constant b =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint constant gx =
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint constant gy =
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    uint constant p =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint constant n =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    uint constant lowSmax =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /**
     * @dev Inverse of u in the field of modulo m.
     */
    function inverseMod(uint u, uint m) internal pure returns (uint) {
        if (u == 0 || u == m || m == 0) return 0;
        if (u > m) u = u % m;

        int t1;
        int t2 = 1;
        uint r1 = m;
        uint r2 = u;
        uint q;
        unchecked {
            while (r2 != 0) {
                q = r1 / r2;
                (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
            }

            if (t1 < 0) return (m - uint(-t1));

            return uint(t1);
        }
    }

    /**
     * @dev Transform affine coordinates into projective coordinates.
     */
    function toProjectivePoint(
        uint x0,
        uint y0
    ) internal pure returns (uint[3] memory P) {
        unchecked {
            P[2] = addmod(0, 1, p);
            P[0] = mulmod(x0, P[2], p);
            P[1] = mulmod(y0, P[2], p);
        }
    }

    /**
     * @dev Add two points in affine coordinates and return projective point.
     */
    function addAndReturnProjectivePoint(
        uint x1,
        uint y1,
        uint x2,
        uint y2
    ) internal pure returns (uint[3] memory P) {
        uint x;
        uint y;
        unchecked {
            (x, y) = add(x1, y1, x2, y2);
        }
        P = toProjectivePoint(x, y);
    }

    /**
     * @dev Transform from projective to affine coordinates.
     */
    function toAffinePoint(
        uint x0,
        uint y0,
        uint z0
    ) internal pure returns (uint x1, uint y1) {
        uint z0Inv;
        unchecked {
            z0Inv = inverseMod(z0, p);
            x1 = mulmod(x0, z0Inv, p);
            y1 = mulmod(y0, z0Inv, p);
        }
    }

    /**
     * @dev Return the zero curve in projective coordinates.
     */
    function zeroProj() internal pure returns (uint x, uint y, uint z) {
        return (0, 1, 0);
    }

    /**
     * @dev Return the zero curve in affine coordinates.
     */
    function zeroAffine() internal pure returns (uint x, uint y) {
        return (0, 0);
    }

    /**
     * @dev Check if the curve is the zero curve.
     */
    function isZeroCurve(uint x0, uint y0) internal pure returns (bool isZero) {
        if (x0 == 0 && y0 == 0) {
            return true;
        }
        return false;
    }

    /**
     * @dev Check if a point in affine coordinates is on the curve.
     */
    function isOnCurve(uint x, uint y) internal pure returns (bool) {
        if (0 == x || x == p || 0 == y || y == p) {
            return false;
        }
        unchecked {
            uint LHS = mulmod(y, y, p); // y^2
            uint RHS = mulmod(mulmod(x, x, p), x, p); // x^3

            if (a != 0) {
                RHS = addmod(RHS, mulmod(x, a, p), p); // x^3 + a*x
            }
            if (b != 0) {
                RHS = addmod(RHS, b, p); // x^3 + a*x + b
            }

            return LHS == RHS;
        }
    }

    /**
     * @dev Double an elliptic curve point in projective coordinates. See
     * https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
     */
    function twiceProj(
        uint x0,
        uint y0,
        uint z0
    ) internal pure returns (uint x1, uint y1, uint z1) {
        uint t;
        uint u;
        uint v;
        uint w;

        if (isZeroCurve(x0, y0)) {
            return zeroProj();
        }
        unchecked {
            u = mulmod(y0, z0, p);
            u = mulmod(u, 2, p);

            v = mulmod(u, x0, p);
            v = mulmod(v, y0, p);
            v = mulmod(v, 2, p);

            x0 = mulmod(x0, x0, p);
            t = mulmod(x0, 3, p);

            z0 = mulmod(z0, z0, p);
            z0 = mulmod(z0, a, p);
            t = addmod(t, z0, p);

            w = mulmod(t, t, p);
            x0 = mulmod(2, v, p);
            w = addmod(w, p - x0, p);

            x0 = addmod(v, p - w, p);
            x0 = mulmod(t, x0, p);
            y0 = mulmod(y0, u, p);
            y0 = mulmod(y0, y0, p);
            y0 = mulmod(2, y0, p);
            y1 = addmod(x0, p - y0, p);

            x1 = mulmod(u, w, p);

            z1 = mulmod(u, u, p);
            z1 = mulmod(z1, u, p);
        }
    }

    /**
     * @dev Add two elliptic curve points in projective coordinates. See
     * https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
     */
    function addProj(
        uint x0,
        uint y0,
        uint z0,
        uint x1,
        uint y1,
        uint z1
    ) internal pure returns (uint x2, uint y2, uint z2) {
        uint t0;
        uint t1;
        uint u0;
        uint u1;

        if (isZeroCurve(x0, y0)) {
            return (x1, y1, z1);
        } else if (isZeroCurve(x1, y1)) {
            return (x0, y0, z0);
        }
        unchecked {
            t0 = mulmod(y0, z1, p);
            t1 = mulmod(y1, z0, p);

            u0 = mulmod(x0, z1, p);
            u1 = mulmod(x1, z0, p);
        }
        if (u0 == u1) {
            if (t0 == t1) {
                return twiceProj(x0, y0, z0);
            } else {
                return zeroProj();
            }
        }
        unchecked {
            (x2, y2, z2) = addProj2(mulmod(z0, z1, p), u0, u1, t1, t0);
        }
    }

    /**
     * @dev Helper function that splits addProj to avoid too many local variables.
     */
    function addProj2(
        uint v,
        uint u0,
        uint u1,
        uint t1,
        uint t0
    ) private pure returns (uint x2, uint y2, uint z2) {
        uint u;
        uint u2;
        uint u3;
        uint w;
        uint t;

        unchecked {
            t = addmod(t0, p - t1, p);
            u = addmod(u0, p - u1, p);
            u2 = mulmod(u, u, p);

            w = mulmod(t, t, p);
            w = mulmod(w, v, p);
            u1 = addmod(u1, u0, p);
            u1 = mulmod(u1, u2, p);
            w = addmod(w, p - u1, p);

            x2 = mulmod(u, w, p);

            u3 = mulmod(u2, u, p);
            u0 = mulmod(u0, u2, p);
            u0 = addmod(u0, p - w, p);
            t = mulmod(t, u0, p);
            t0 = mulmod(t0, u3, p);

            y2 = addmod(t, p - t0, p);

            z2 = mulmod(u3, v, p);
        }
    }

    /**
     * @dev Add two elliptic curve points in affine coordinates.
     */
    function add(
        uint x0,
        uint y0,
        uint x1,
        uint y1
    ) internal pure returns (uint, uint) {
        uint z0;

        (x0, y0, z0) = addProj(x0, y0, 1, x1, y1, 1);

        return toAffinePoint(x0, y0, z0);
    }

    /**
     * @dev Double an elliptic curve point in affine coordinates.
     */
    function twice(uint x0, uint y0) internal pure returns (uint, uint) {
        uint z0;

        (x0, y0, z0) = twiceProj(x0, y0, 1);

        return toAffinePoint(x0, y0, z0);
    }

    /**
     * @dev Multiply an elliptic curve point by a 2 power base (i.e., (2^exp)*P)).
     */
    function multiplyPowerBase2(
        uint x0,
        uint y0,
        uint exp
    ) internal pure returns (uint, uint) {
        uint base2X = x0;
        uint base2Y = y0;
        uint base2Z = 1;

        for (uint i = 0; i < exp; i++) {
            (base2X, base2Y, base2Z) = twiceProj(base2X, base2Y, base2Z);
        }

        return toAffinePoint(base2X, base2Y, base2Z);
    }

    /**
     * @dev Multiply an elliptic curve point by a scalar.
     */
    function multiplyScalar(
        uint x0,
        uint y0,
        uint scalar
    ) internal pure returns (uint x1, uint y1) {
        if (scalar == 0) {
            return zeroAffine();
        } else if (scalar == 1) {
            return (x0, y0);
        } else if (scalar == 2) {
            return twice(x0, y0);
        }

        uint base2X = x0;
        uint base2Y = y0;
        uint base2Z = 1;
        uint z1 = 1;
        x1 = x0;
        y1 = y0;

        if (scalar % 2 == 0) {
            x1 = y1 = 0;
        }

        scalar = scalar >> 1;

        while (scalar > 0) {
            (base2X, base2Y, base2Z) = twiceProj(base2X, base2Y, base2Z);

            if (scalar % 2 == 1) {
                (x1, y1, z1) = addProj(base2X, base2Y, base2Z, x1, y1, z1);
            }

            scalar = scalar >> 1;
        }

        return toAffinePoint(x1, y1, z1);
    }

 /**
     * @dev Double base multiplication using windowing and Shamir's trick
     */
    function ec_mulmuladd(
        uint Gx0,
        uint Gy0,
        uint Qx0,
        uint Qy0,
        uint scalar_u,
        uint scalar_v
    ) internal pure returns (uint[3] memory R) {
        
      /*1. Precomputation steps: 2 bits window+shamir */  
      /* precompute all aG+bQ in [0..3][0..3]*/
      uint [3][16] memory Window;
      Window[1][0]=Gx0;
      Window[1][1]=Gy0;
      Window[1][2]=1;
      
      Window[2][0]=Qx0;
      Window[2][1]=Qy0;
      Window[2][2]=1;

      (Window[3][0], Window[3][1], Window[3][2])=addProj(Gx0, Gy0, 1, Qx0, Gy0, 1); //3:G+Q
      (Window[4][0], Window[4][1], Window[4][2])=twiceProj(Gx0, Gy0, 1);//4:2G
      (Window[5][0], Window[5][1], Window[5][2])=addProj(Gx0, Gy0, 1, Window[4][0], Window[4][1], Window[4][2]); //5:3G
      (Window[6][0], Window[6][1], Window[6][2])=addProj(Qx0, Qy0, 1, Window[4][0], Window[4][1], Window[4][2]); //6:2G+Q
      (Window[7][0], Window[7][1], Window[7][2])=addProj(Qx0, Qy0, 1, Window[5][0], Window[5][1], Window[5][2]); //7:3G+Q
      (Window[8][0], Window[8][1], Window[8][2])=twiceProj(Window[4][0], Window[4][1], Window[4][2]);//8:4G
     
      (Window[9][0], Window[9][1], Window[9][2])=addProj(Gx0, Gy0, 1, Window[8][0], Window[8][1], Window[8][2]);//9:2Q+G
      (Window[10][0], Window[10][1], Window[10][2])=addProj(Qx0, Qy0, 1, Window[8][0], Window[8][1], Window[8][2]);//10:3Q
      (Window[11][0], Window[11][1], Window[11][2])=addProj(Gx0, Gy0, 1, Window[10][0], Window[10][1], Window[10][2]); //11:3Q+G
      (Window[12][0], Window[12][1], Window[12][2])=addProj(Window[8][0], Window[8][1], Window[8][2] , Window[4][0], Window[4][1], Window[4][2]); //12:2Q+2G
      (Window[13][0], Window[13][1], Window[13][2])=addProj(Window[8][0], Window[8][1], Window[8][2] , Window[5][0], Window[5][1], Window[5][2]); //13:2Q+3G
      (Window[14][0], Window[14][1], Window[14][2])=addProj(Window[10][0], Window[10][1], Window[10][2], Window[4][0], Window[4][1], Window[4][2]); //14:3Q+2G
      (Window[15][0], Window[15][1], Window[15][2])=addProj(Window[10][0], Window[10][1], Window[10][2],  Window[5][0], Window[5][1], Window[5][2]); //15:3Q+3G
    
    
     //initialize R with infinity point
      R[0]=0;
      R[1]=0;
      R[2]=0;
     uint quadbit=1;
     //2. loop over scalars from MSB to LSB:
     for(uint8 i=0;i<128;i++)
     {
       uint8 rshift=255-2*i; 
       (R[0],R[1],R[2])=twiceProj(R[0],R[1],R[2]);//double
       (R[0],R[1],R[2])=twiceProj(R[0],R[1],R[2]);//double
       
     //compute quadruple (8*v1 +4*u1+ 2*v0 + u0)
      	quadbit=8*((scalar_u>>rshift)&1)+ 4*((scalar_u>>rshift)&1)+ 2*((scalar_v>>(rshift-1))&1)+ ((scalar_u >>(rshift-1))&1);
        (R[0],R[1],R[2])=addProj(R[0],R[1],R[2], Window[quadbit][0], Window[quadbit][1], Window[quadbit][2]);     
     }
     
      return R;
    }


    /**
     * @dev Multiply the curve's generator point by a scalar.
     */
    function multipleGeneratorByScalar(
        uint scalar
    ) internal pure returns (uint, uint) {
        return multiplyScalar(gx, gy, scalar);
    }

    /**
     * @dev Validate combination of message, signature, and public key.
     */
    function validateSignature(
        bytes32 message,
        uint[2] memory rs,
        uint[2] memory Q
    ) internal pure returns (bool) {
        // To disambiguate between public key solutions, include comment below.
        if (rs[0] == 0 || rs[0] >= n || rs[1] == 0) {
            // || rs[1] > lowSmax)
            return false;
        }
        if (!isOnCurve(Q[0], Q[1])) {
            return false;
        }

        uint x1;
        uint x2;
        uint y1;
        uint y2;

        uint sInv = inverseMod(rs[1], n);
        
        // without Optim
        /*
        (x1, y1) = multiplyScalar(gx, gy, mulmod(uint(message), sInv, n));
        (x2, y2) = multiplyScalar(Q[0], Q[1], mulmod(rs[0], sInv, n));
        uint[3] memory P = addAndReturnProjectivePoint(x1, y1, x2, y2);
        */
        
        uint scalar_v=mulmod(uint(message), sInv, n);
        uint scalar_u= mulmod(rs[0], sInv, n);
 	uint[3] memory P = ec_mulmuladd(gx, gy, Q[0], Q[1],scalar_v ,scalar_u );
 	
	


        if (P[2] == 0) {
            return false;
        }

        uint Px = inverseMod(P[2], p);
        unchecked {
            Px = mulmod(P[0], mulmod(Px, Px, p), p);
        }

        return Px % n == rs[0];
    }
}
