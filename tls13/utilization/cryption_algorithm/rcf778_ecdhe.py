# -*- coding: UTF-8 -*-
# Elliptic Curve : v^2 = u^3 + A*u^2 + u

def x25519():
    p = pow(2, 255) - 19
    A = 486662


def x448():
    p = pow(2, 448) - pow(2, 224) - 1
    A = 156326


'''
4.1.  Curve25519

   For the ~128-bit security level, the prime 2^255 - 19 is recommended
   for performance on a wide range of architectures.  Few primes of the
   form 2^c-s with s small exist between 2^250 and 2^521, and other
   choices of coefficient are not as competitive in performance.  This
   prime is congruent to 1 mod 4, and the derivation procedure in
   Appendix A results in the following Montgomery curve
   v^2 = u^3 + A*u^2 + u, called "curve25519":

   p  2^255 - 19

   A  486662

   order  2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed

   cofactor  8

   U(P)  9

   V(P)  147816194475895447910205935684099868872646061346164752889648818
      37755586237401

   The base point is u = 9, v = 1478161944758954479102059356840998688726
   4606134616475288964881837755586237401.

   This curve is birationally equivalent to a twisted Edwards curve -x^2
   + y^2 = 1 + d*x^2*y^2, called "edwards25519", where:

   p  2^255 - 19

   d  370957059346694393431380835087545651895421138798432190163887855330
      85940283555

   order  2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed

   cofactor  8

   X(P)  151122213495354007725011514095885315114540126930418572060461132
      83949847762202

   Y(P)  463168356949264781694283940034751631413079938662562256157830336
      03165251855960

   The birational maps are:

     (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
     (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))

   The Montgomery curve defined here is equal to the one defined in
   [curve25519], and the equivalent twisted Edwards curve is equal to
   the one defined in [ed25519].

4.2.  Curve448

   For the ~224-bit security level, the prime 2^448 - 2^224 - 1 is
   recommended for performance on a wide range of architectures.  This
   prime is congruent to 3 mod 4, and the derivation procedure in
   Appendix A results in the following Montgomery curve, called
   "curve448":

   p  2^448 - 2^224 - 1

   A  156326

   order  2^446 -
      0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d

   cofactor  4

   U(P)  5

   V(P)  355293926785568175264127502063783334808976399387714271831880898
      435169088786967410002932673765864550910142774147268105838985595290
      606362

   This curve is birationally equivalent to the Edwards curve x^2 + y^2
   = 1 + d*x^2*y^2 where:

   p  2^448 - 2^224 - 1

   d  611975850744529176160423220965553317543219696871016626328968936415
      087860042636474891785599283666020414768678979989378147065462815545
      017

   order  2^446 -
      0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d

   cofactor  4


   X(P)  345397493039729516374008604150537410266655260075183290216406970
      281645695073672344430481787759340633221708391583424041788924124567
      700732

   Y(P)  363419362147803445274661903944002267176820680343659030140745099
      590306164083365386343198191849338272965044442230921818680526749009
      182718

   The birational maps are:

     (u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)
     (x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))

   Both of those curves are also 4-isogenous to the following Edwards
   curve x^2 + y^2 = 1 + d*x^2*y^2, called "edwards448", where:

   p  2^448 - 2^224 - 1

   d  -39081

   order  2^446 -
      0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d

   cofactor  4

   X(P)  224580040295924300187604334099896036246789641632564134246125461
      686950415467406032909029192869357953282578032075146446173674602635
      247710

   Y(P)  298819210078481492676017930443930673437544040154080242095928241
      372331506189835876003536878655418784733982303233503462500531545062
      832660

   The 4-isogeny maps between the Montgomery curve and this Edwards
   curve are:

     (u, v) = (y^2/x^2, (2 - x^2 - y^2)*y/x^3)
     (x, y) = (4*v*(u^2 - 1)/(u^4 - 2*u^2 + 4*v^2 + 1),
               -(u^5 - 2*u^3 - 4*u*v^2 + u)/
               (u^5 - 2*u^2*v^2 - 2*u^3 - 2*v^2 + u))

   The curve edwards448 defined here is also called "Goldilocks" and is
   equal to the one defined in [goldilocks].

'''