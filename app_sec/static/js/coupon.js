function askForCoupon() {
    let couponCode = prompt("Please enter your coupon code:");
    if (couponCode) {
        applyCoupon(couponCode);
    }
}

function applyCoupon() {
    var couponCode = prompt("Please enter your coupon code:");
    if (couponCode) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/apply_coupon", true);
        xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
        xhr.onload = function() {
            if (xhr.status === 200) {
                print("Coupon code applied successfully.")
                var response = JSON.parse(xhr.responseText);
                var updatedPrice = response.updated_price;
                document.getElementById('total').textContent = '$' + updatedPrice.toFixed(2);
                alert(response.message);
            } else {
                alert("Coupon code processing failed.");
            }
        };
        xhr.send(JSON.stringify({ coupon: couponCode }));
    }
}