from passlib.hash import md5_crypt

REF_SK = "$1$de4df4ce$UHK.oW4FQLqoAsg6znrNq/"
REF_TEST = "$1$de4df4ce$gRNZW.h1MMWTnvH.8Q2az0"
REF_MORT = "$1$de4df4ce$66TtQpFqk.mMDh7Fct2ux/"

pl_sk = md5_crypt.using(salt="de4df4ce").hash("Sk4t3rB0y_S1nce_2011")
pl_test = md5_crypt.using(salt="de4df4ce").hash("test")
pl_mort = md5_crypt.using(salt="de4df4ce").hash("mort1cia")

print("passlib sk   :", pl_sk)
print("openssl sk   :", REF_SK)
print("passlib test :", pl_test)
print("openssl test :", REF_TEST)
print("passlib mort :", pl_mort)
print("openssl mort :", REF_MORT)
print("ALL MATCH:", pl_sk == REF_SK and pl_test == REF_TEST and pl_mort == REF_MORT)
