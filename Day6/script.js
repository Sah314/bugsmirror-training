// Java.perform(function () {
//     var CodeCheck = Java.use("sg.vantagepoint.a.a");

//     // Create an instance of the class
//     //var codeCheckInstance = CodeCheck.$new();

//     // Intercept the 'a' method
//     CodeCheck.a.overload('[B', '[B').implementation = function (bArr1, bArr2) {
//       console.log("bArr1: ", bArr1);
//       console.log("bArr2: ", bArr2);
//       var codeCheckInstance;
//       try {
//     codeCheckInstance = CodeCheck.$new();   
//       } catch (error) {
//         console.error(error)
//       }
     

//     // Call the original method on the instance
//     var result = this.a(bArr1, bArr2);
       
//         console.log("[*] Intercepted 'a' method with result:", result);
    
//             console.log("type of result:", typeof Memory.readUtf8String(result));
            
    

//         // Return the original or modified result
//         return result;
//     };
// });


Java.perform(function () {
    var CodeCheck = Java.use("sg.vantagepoint.a.a");

    // Intercept the 'a' method
    CodeCheck.a.overload('[B', '[B').implementation = function (bArr1, bArr2) {
        // console.log("bArr1: ", byteArrayToUnsigned(bArr1));
        // console.log("bArr2: ", byteArrayToUnsigned(bArr2));

        // Create an instance of the class (if needed)
        var codeCheckInstance;
        try {
            codeCheckInstance = CodeCheck.$new();
        } catch (error) {
            console.error(error);
        }

        // Call the original method on the instance (if created)
        var result;
        try {
            result = this.a(bArr1, bArr2);
        } catch (error) {
            console.error("Error calling 'a' method:", error);
            // You might need additional error handling based on the actual structure of the 'result'
        }

        // Check if result is an array and read the first element as a UTF-8 string
       try {
        console.log("[*] Intercepted 'a' method with result:", result);

        var resultString = String.fromCharCode.apply(null, result);

        console.log(resultString);
       } catch (error) {
        console.error(error)
       }
          

        // Return the original or modified result
        return result;
    };
});
