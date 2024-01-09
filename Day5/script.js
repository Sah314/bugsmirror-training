// Replace "libfoo.so" with the actual library name
var moduleName = 'libfoo.so';
//var strncmpAddress = Module.findExportByName(moduleName, 'strncmp');
// function onClick(){

// }

setTimeout(() => {
    Interceptor.attach(Module.findExportByName(moduleName, 'strncmp'),{
        onEnter:function(args){
            try {
                var v1 =Memory.readUtf8String(args[0])
                var v2 =Memory.readUtf8String(args[1])
                if(v1.includes("abcdefghijklmnopqrstuvw") || v2.includes("abcdefghijklmnopqrstuvw")){
                    console.log(v1,v2);
                }
                //console.log(Memory.readUtf8String(args));
                
            } catch (error) {
                console.error(error)
            }
            
    

            //console.log('strncmp called with:', str1, str2);

        },
        onLeave:function(retval){
    
        }
    
    });
    
}, 5000);
    

// if (strncmpAddress) {
//     console.log('Found strncmp at address:', strncmpAddress);

//     // Create a NativeFunction for strncmp
//     var strncmp = new NativeFunction(strncmpAddress, 'int', ['pointer', 'pointer', 'size_t']);

//     // Intercept strncmp
//     Interceptor.replace(strncmp, new NativeCallback(function (str1, str2, size) {
//         // Convert the pointers to strings
//         var string1 = Memory.readUtf8String(str1, size);
//         var string2 = Memory.readUtf8String(str2, size);
        
//         // Log the arguments and modify the result
//         console.log('strncmp called with:', string1, string2, size);
        
//         // Bypass the original check by returning a non-zero value
//         return 1;
//     }, 'int', ['pointer', 'pointer', 'size_t']));
// } else {
//     console.error('strncmp not found in', moduleName);
// }
