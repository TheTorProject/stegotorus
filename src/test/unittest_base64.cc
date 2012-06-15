/* Copyright 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "unittest.h"
#include "base64.h"

struct testvec
{
  const char *dec;
  const char *enc;
  size_t declen;
  size_t enclen;
};

#define S_(x) #x
#define S(x) S_(x)

const struct testvec testvecs[] = {
  // padding tests from RFC 4648
  { "",       "",         0, 0 },
  { "f",      "Zg==",     1, 4 },
  { "fo",     "Zm8=",     2, 4 },
  { "foo",    "Zm9v",     3, 4 },
  { "foob",   "Zm9vYg==", 4, 8 },
  { "fooba",  "Zm9vYmE=", 5, 8 },
  { "foobar", "Zm9vYmFy", 6, 8 },

  // all single bytes
#define B(b,e) { S(\x##b), S(e==), 1, 4 }
  B(00,AA), B(01,AQ), B(02,Ag), B(03,Aw), B(04,BA), B(05,BQ), B(06,Bg),
  B(07,Bw), B(08,CA), B(09,CQ), B(0a,Cg), B(0b,Cw), B(0c,DA), B(0d,DQ),
  B(0e,Dg), B(0f,Dw), B(10,EA), B(11,EQ), B(12,Eg), B(13,Ew), B(14,FA),
  B(15,FQ), B(16,Fg), B(17,Fw), B(18,GA), B(19,GQ), B(1a,Gg), B(1b,Gw),
  B(1c,HA), B(1d,HQ), B(1e,Hg), B(1f,Hw), B(20,IA), B(21,IQ), B(22,Ig),
  B(23,Iw), B(24,JA), B(25,JQ), B(26,Jg), B(27,Jw), B(28,KA), B(29,KQ),
  B(2a,Kg), B(2b,Kw), B(2c,LA), B(2d,LQ), B(2e,Lg), B(2f,Lw), B(30,MA),
  B(31,MQ), B(32,Mg), B(33,Mw), B(34,NA), B(35,NQ), B(36,Ng), B(37,Nw),
  B(38,OA), B(39,OQ), B(3a,Og), B(3b,Ow), B(3c,PA), B(3d,PQ), B(3e,Pg),
  B(3f,Pw), B(40,QA), B(41,QQ), B(42,Qg), B(43,Qw), B(44,RA), B(45,RQ),
  B(46,Rg), B(47,Rw), B(48,SA), B(49,SQ), B(4a,Sg), B(4b,Sw), B(4c,TA),
  B(4d,TQ), B(4e,Tg), B(4f,Tw), B(50,UA), B(51,UQ), B(52,Ug), B(53,Uw),
  B(54,VA), B(55,VQ), B(56,Vg), B(57,Vw), B(58,WA), B(59,WQ), B(5a,Wg),
  B(5b,Ww), B(5c,XA), B(5d,XQ), B(5e,Xg), B(5f,Xw), B(60,YA), B(61,YQ),
  B(62,Yg), B(63,Yw), B(64,ZA), B(65,ZQ), B(66,Zg), B(67,Zw), B(68,aA),
  B(69,aQ), B(6a,ag), B(6b,aw), B(6c,bA), B(6d,bQ), B(6e,bg), B(6f,bw),
  B(70,cA), B(71,cQ), B(72,cg), B(73,cw), B(74,dA), B(75,dQ), B(76,dg),
  B(77,dw), B(78,eA), B(79,eQ), B(7a,eg), B(7b,ew), B(7c,fA), B(7d,fQ),
  B(7e,fg), B(7f,fw), B(80,gA), B(81,gQ), B(82,gg), B(83,gw), B(84,hA),
  B(85,hQ), B(86,hg), B(87,hw), B(88,iA), B(89,iQ), B(8a,ig), B(8b,iw),
  B(8c,jA), B(8d,jQ), B(8e,jg), B(8f,jw), B(90,kA), B(91,kQ), B(92,kg),
  B(93,kw), B(94,lA), B(95,lQ), B(96,lg), B(97,lw), B(98,mA), B(99,mQ),
  B(9a,mg), B(9b,mw), B(9c,nA), B(9d,nQ), B(9e,ng), B(9f,nw), B(a0,oA),
  B(a1,oQ), B(a2,og), B(a3,ow), B(a4,pA), B(a5,pQ), B(a6,pg), B(a7,pw),
  B(a8,qA), B(a9,qQ), B(aa,qg), B(ab,qw), B(ac,rA), B(ad,rQ), B(ae,rg),
  B(af,rw), B(b0,sA), B(b1,sQ), B(b2,sg), B(b3,sw), B(b4,tA), B(b5,tQ),
  B(b6,tg), B(b7,tw), B(b8,uA), B(b9,uQ), B(ba,ug), B(bb,uw), B(bc,vA),
  B(bd,vQ), B(be,vg), B(bf,vw), B(c0,wA), B(c1,wQ), B(c2,wg), B(c3,ww),
  B(c4,xA), B(c5,xQ), B(c6,xg), B(c7,xw), B(c8,yA), B(c9,yQ), B(ca,yg),
  B(cb,yw), B(cc,zA), B(cd,zQ), B(ce,zg), B(cf,zw), B(d0,0A), B(d1,0Q),
  B(d2,0g), B(d3,0w), B(d4,1A), B(d5,1Q), B(d6,1g), B(d7,1w), B(d8,2A),
  B(d9,2Q), B(da,2g), B(db,2w), B(dc,3A), B(dd,3Q), B(de,3g), B(df,3w),
  B(e0,4A), B(e1,4Q), B(e2,4g), B(e3,4w), B(e4,5A), B(e5,5Q), B(e6,5g),
  B(e7,5w), B(e8,6A), B(e9,6Q), B(ea,6g), B(eb,6w), B(ec,7A), B(ed,7Q),
  B(ee,7g), B(ef,7w), B(f0,8A), B(f1,8Q), B(f2,8g), B(f3,8w), B(f4,9A),
  B(f5,9Q), B(f6,9g), B(f7,9w), B(f8,+A), B(f9,+Q), B(fa,+g), B(fb,+w),
  B(fc,/A), B(fd,/Q), B(fe,/g), B(ff,/w),
#undef B

  // all single base64 digits, padded on the left and the right with an A
#define D(d1,d2,e) { S(\x##d1\x##d2), "A" S(e) "A=", 2, 4 }
  D(00,00,A), D(00,10,B), D(00,20,C), D(00,30,D), D(00,40,E),
  D(00,50,F), D(00,60,G), D(00,70,H), D(00,80,I), D(00,90,J),
  D(00,a0,K), D(00,b0,L), D(00,c0,M), D(00,d0,N), D(00,e0,O),
  D(00,f0,P), D(01,00,Q), D(01,10,R), D(01,20,S), D(01,30,T),
  D(01,40,U), D(01,50,V), D(01,60,W), D(01,70,X), D(01,80,Y),
  D(01,90,Z), D(01,a0,a), D(01,b0,b), D(01,c0,c), D(01,d0,d),
  D(01,e0,e), D(01,f0,f), D(02,00,g), D(02,10,h), D(02,20,i),
  D(02,30,j), D(02,40,k), D(02,50,l), D(02,60,m), D(02,70,n),
  D(02,80,o), D(02,90,p), D(02,a0,q), D(02,b0,r), D(02,c0,s),
  D(02,d0,t), D(02,e0,u), D(02,f0,v), D(03,00,w), D(03,10,x),
  D(03,20,y), D(03,30,z), D(03,40,0), D(03,50,1), D(03,60,2),
  D(03,70,3), D(03,80,4), D(03,90,5), D(03,a0,6), D(03,b0,7),
  D(03,c0,8), D(03,d0,9), D(03,e0,+), D(03,f0,/),
#undef D

  { 0, 0, 0, 0 }
};


static void
test_base64_standard(void *)
{
  base64::encoder E(false);
  base64::decoder D;

  char buf[16];

  for (const struct testvec *tv = testvecs; tv->dec; tv++) {
    size_t len = E.encode(tv->dec, tv->declen, buf);
    E.encode_end(buf + len);
    tt_str_op(buf, ==, tv->enc);

    len = D.decode(tv->enc, tv->enclen, buf);
    D.reset();
    tt_uint_op(len, ==, tv->declen);
    tt_mem_op(buf, ==, tv->dec, tv->declen);
  }

 end:;
}

static void
test_base64_altpunct(void *)
{
  base64::encoder E(false, '-', '_', '.');
  base64::decoder D('-', '_', '.');

  char buf[16];
  char cenc[16];

  for (const struct testvec *tv = testvecs; tv->dec; tv++) {
    memcpy(cenc, tv->enc, tv->enclen);
    cenc[tv->enclen] = '\0';
    for (size_t i = 0; i < tv->enclen; i++)
      switch (cenc[i]) {
      default: break;
      case '+': cenc[i] = '-'; break;
      case '/': cenc[i] = '_'; break;
      case '=': cenc[i] = '.'; break;
      }

    size_t len = E.encode(tv->dec, tv->declen, buf);
    E.encode_end(buf + len);
    tt_str_op(buf, ==, cenc);

    len = D.decode(cenc, tv->enclen, buf);
    D.reset();
    tt_uint_op(len, ==, tv->declen);
    tt_mem_op(buf, ==, tv->dec, tv->declen);
  }

 end:;
}

static void
test_base64_wrapping(void *)
{
  const char in[] =
    "..........................................."
    "..........................................."
    "...........................................";
  const char out[] =
    "Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4"
    "uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi"
    "4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uL"
    "i4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4u";
  const char outw[] =
    "Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4u\n"
    "Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4u\n"
    "Li4uLi4uLi4uLi4uLi4uLi4uLi4u";

  base64::encoder E(false);
  base64::encoder Ew(true);

  char buf[256];
  size_t len;

  for (size_t nc = 0; nc <= 129; nc += 3) {
    memset(buf, 0, sizeof buf);

    len  = E.encode(in, nc, buf);
    len += E.encode_end(buf + len);
    tt_stn_op(buf, ==, out, len);

    len  = Ew.encode(in, nc, buf);
    len += Ew.encode_end(buf + len);
    tt_stn_op(buf, ==, outw, len-1);
    tt_char_op(buf[len-1], ==, '\n');
  }

 end:;
}

#define T(name) \
  { #name, test_base64_##name, 0, 0, 0 }

struct testcase_t base64_tests[] = {
  T(standard),
  T(altpunct),
  T(wrapping),
  END_OF_TESTCASES
};
