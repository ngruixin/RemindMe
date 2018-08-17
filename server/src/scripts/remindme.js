SERVER_IP = "127.0.0.1"
SERVER_PORT = "8080" 
HOST = "http://" + SERVER_IP + ":" + SERVER_PORT + "/"

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
	post("register.html", post_data, "Registration failed, please try again.") 
}

function login() {
	var username = $("#username").val();
	var password = $("#password").val();
	var post_data = JSON.stringify({"username": username, "password": password});
	post("login.html", post_data, "Login failed, please try again.")
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

function post(uri, post_data, failure_msg) {
	console.log(post_data);
	console.log(HOST + uri);
	$.ajax({
	    url: HOST + uri,
	    dataType: 'json',
	    type: 'post',
	    contentType: 'application/json',
		data: post_data,
		success: function( data, textStatus, jQxhr ){
	        $('#response pre').html( JSON.stringify( data ) );
	        window.location = "reminder.html"; 
	    },
	    error: function( jqXhr, textStatus, errorThrown ){
	        console.log( errorThrown );
	    }
	})
	//return false; #TODO SHOULD RETURN FALSE
}


