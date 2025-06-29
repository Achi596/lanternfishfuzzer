
Interceptor.attach(Module.findExportByName(null, 'strcpy'), {
    onEnter: function(args) {
        var dest = args[0].readUtf8String();
        var src = args[1].readUtf8String();
        console.log('strcpy called with dest: ' + dest + ' and src: ' + src);

        // Check if source is too large for destination (simple buffer overflow check)
        if (src.length > dest.length) {
            console.log('Possible buffer overflow detected: source is larger than destination');
        }
    },
    onLeave: function(retval) {
        // Optionally modify return value or perform additional checks
    }
});


Interceptor.attach(Module.findExportByName(null, 'strncpy'), {
    onEnter: function(args) {
        var dest = args[0].readUtf8String();
        var src = args[1].readUtf8String();
	var num = args[2].toInt32();

	console.log('strncpy called');
	console.log('Destination: ', dest);
	console.log('Source: ', src);
	console.log('Number of bytes to transfer: ', num);

	

        // Check if source is too large for destination (simple buffer overflow check)
        if (src.length > dest.length && num > dest.length) {
	    console.log('Buffer overflow detected');
	    console.log('Source size: ', src.length);
	    console.log('Destination size: ', dest.length);
	    console.log('Number of bytes to transfer: ', num);
        }
    },
    onLeave: function(retval) {
        // Optionally modify return value or perform additional checks
    }
});


