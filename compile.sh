export CROSS_COMPILE_HOST=$CROSS_COMPILE
export CROSS_COMPILE_TA=$CROSS_COMPILE
if [ -z "$INSTALL_MOD_PATH" ];then
echo Please specify INSTALL_MOD_PATH; exit 1
fi

if [ "$1" != "clean" ]; then
if [ -d images ]; then
	rm -rf images;
fi

echo "Building Secure Storage TA";
cd secure_storage_ta;
make clean;
make;
cd -;
echo ""

echo "Building Secure Key Kernel Module";
cd securekeydev;
make clean;
make;
make modules_install;
cd -;

echo "Building Secure Object Library";
cd securekey_lib;
make clean;
make;
cd -;

echo "Building Secure Object OpenSSL Engine";
cd secure_obj-openssl-engine;
make clean;
make;
cd -;

mkdir images;
cp secure_storage_ta/ta/b05bcf48-9732-4efa-a9e0-141c7c888c34.ta images;
cp securekey_lib/out/export/lib/libsecure_obj.so images;
cp securekey_lib/out/export/app/* images;
cp securekeydev/securekeydev.ko images;
cp secure_obj-openssl-engine/libeng_secure_obj.so secure_obj-openssl-engine/app/sobj_eng_app images;
else
echo "Cleaning TA, Secure Obj Lib and Securekeydev"
cd secure_storage_ta;
make clean;
cd -;
cd securekeydev;
make clean;
cd -;
cd securekey_lib;
make clean;
cd -;
cd secure_obj-openssl-engine;
make clean;
cd -;
rm -rf images;
fi
