Java.perform(function () {
    var MainActivity = Java.use("sg.vantagepoint.uncrackable2.MainActivity");

    // Intercept the verify method
    MainActivity.verify.overload('android.view.View').implementation = function (view) {
        // Access the EditText instance
        var editText = this.findViewById(0x7f070035); // Replace with the actual ID of your EditText
        //console.log(editText);
        // Get the text from the EditText
        //var inputText = editText.getText().toString();
        var nativeEditText = Java.cast(editText, Java.use("android.widget.EditText"));

        // Get the text from the EditText
       // var inputText = getTextMethod.invoke(nativeEditText, []);
        var inputText = nativeEditText.getText();
        // Log method call and input
        console.log('verify method is called with input:', JSON.stringify(inputText));

    

        // You can add your custom logic or actions here

        // Call the original method
        this.verify(view);
    };
});
