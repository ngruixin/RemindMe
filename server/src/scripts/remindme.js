SERVER_IP = ""
SERVER_PORT = ""

$(document).ready(function() {
	
	$("#register").click(register);
	$("#login").click(login)
	$("#save").click(save)
	$('#start').datepicker();
	$('#end').datepicker();
	
});

function register() {
	var username = $("#username").val();
	var password = $("#password").val();
	var cfm_pwd = $("#cfm_pwd").val();
	if (password != cfm_pwd) {
		alert("Please make sure that the passwords match! ")
		return;
	}
	var post_data = JSON.stringify({"username": username, "password": password});
	if (post(post_data)) window.location = "login.html"; 
	else alert("Registration failed, please try again.")
}

function login() {
	var username = $("#username").val();
	var password = $("#password").val();
	var post_data = JSON.stringify({"username": username, "password": password});
	if (post(post_data)) window.location = "reminder.html"; 
	else alert("Login failed, please try again.")
}

function save() {
	//run through each row
	var name = $('#name').val();
    console.log(name);
    $('tr.item').each(function () {
        var name = $(this).find('input.name').val();
        console.log(name);
    });
}

function post(post_data) {
	console.log(post_data);
	return true;
	// ajax?? 
	/*$.ajax({
	  type: 'POST',
	  url: form.attr('action'),
	  data: form.serialize(), // serializes form elements
	  success: function(response) {
	    // re-writes the entire document
	    var newDoc = document.open("text/html", "replace");
	    newDoc.write(response);
	    newDoc.close();
	  }
	});*/
}


