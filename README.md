# Modbus network fuzzer
### Network fuzzer for the modbus protocol

The modbus network fuzzer uses Boofuzz for the fuzzing of the protocol. 

![fuzzing_2](https://user-images.githubusercontent.com/5167692/230782624-acee0465-8463-4deb-97fc-2e628d027046.png)



Installation:
```
python3 -m pip install -r requirements.txt
```

Running the fuzzer:
````
python3 modbus.py IP Port

Python3 modbus.py 10.10.10.10 502

````


Be aware fuzzing can take time. If you run the all function codes it takes a long time due to many test cases.<br>
It is possible to run multible instances of the of the fuzzer on the same test pc. 

-------------------------------------------------------------------------------------------------

The modbus fuzzer is managed by Egede and attributions and support from other is verry welcome 😊

