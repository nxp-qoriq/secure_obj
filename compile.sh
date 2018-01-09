export CROSS_COMPILE_HOST=$CROSS_COMPILE
export CROSS_COMPILE_TA=$CROSS_COMPILE


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

echo "Building Secure Object Library";
cd securekey_lib;
make clean;
make;
cd -;

mkdir images;
cp secure_storage_ta/ta/b05bcf48-9732-4efa-a9e0-141c7c888c34.ta images;
cp securekey_lib/out/export/lib/libsecure_obj.so images;
cp securekey_lib/out/export/app/* images;
else
echo "Cleaning TA and Lib"
cd secure_storage_ta;
make clean;
cd -;
cd securekey_lib;
make clean;
cd -;
rm -rf images;
fi
