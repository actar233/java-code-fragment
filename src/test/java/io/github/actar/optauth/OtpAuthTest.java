package io.github.actar.optauth;

public class OtpAuthTest {

    public static void main(String[] args) {

        OtpAuth otpAuth = OtpAuth.totp("Example", "test@mail.com", "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", null, null, null);

        System.out.println(otpAuth.toUri());

        otpAuth = OtpAuth.parse(otpAuth.toUri());

        System.out.println(otpAuth.toUri());

    }

}
