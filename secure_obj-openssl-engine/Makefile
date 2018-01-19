#Makefile for eng_secure_obj

INCLUDES = -I./ -I${OPENSSL_PATH}/ -I${OPENSSL_PATH}/include/ -I${OPENSSL_PATH}/crypto/include/ -I../securekey_lib/include/

all :

	${CC} -fPIC -g -o eng_secure_obj.o -c eng_secure_obj.c $(INCLUDES)
	${CC} -shared -fPIC -o libeng_secure_obj.so *.o -lpthread -L${OPENSSL_PATH} -lcrypto -L../securekey_lib/out/securekey_lib -lsecure_obj

clean :
	rm *.o *.so
