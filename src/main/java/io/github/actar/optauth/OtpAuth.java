package io.github.actar.optauth;

/**
 * OtpAuth 协议解析和构造
 */
public class OtpAuth {

    public static enum Type {
        HOTP,
        TOTP,
    }

    public static enum Algorithm {
        SHA1,
        SHA256,
        SHA512,
    }

    public static OtpAuth hotp(String issuer, String accountName, String secret, Algorithm algorithm, Integer digits, Integer counter) {
        final OtpAuth otpAuth = new OtpAuth();
        otpAuth.type = Type.HOTP;
        String label;
        if (issuer == null) {
            label = accountName;
        } else {
            label = String.format("%s:%s", issuer, accountName);
        }
        otpAuth.label = label;
        otpAuth.issuer = issuer;
        otpAuth.accountName = accountName;
        otpAuth.secret = secret;
        if (algorithm == null) {
            algorithm = Algorithm.SHA1;
        }
        otpAuth.algorithm = algorithm;
        if (digits == null) {
            digits = 6;
        }
        otpAuth.digits = digits;
        otpAuth.counter = counter;
        return otpAuth;
    }

    public static OtpAuth totp(String issuer, String accountName, String secret, Algorithm algorithm, Integer digits, Integer period) {
        final OtpAuth otpAuth = new OtpAuth();
        otpAuth.type = Type.TOTP;
        String label;
        if (issuer == null) {
            label = accountName;
        } else {
            label = String.format("%s:%s", issuer, accountName);
        }
        otpAuth.label = label;
        otpAuth.issuer = issuer;
        otpAuth.accountName = accountName;
        otpAuth.secret = secret;
        if (algorithm == null) {
            algorithm = Algorithm.SHA1;
        }
        otpAuth.algorithm = algorithm;
        if (digits == null) {
            digits = 6;
        }
        otpAuth.digits = digits;
        if (period == null) {
            period = 30;
        }
        otpAuth.period = period;
        return otpAuth;
    }

    public static OtpAuth parse(String uri) {
        final String PROTOCOL = "otpauth://";
        final String TYPE_HOTP = "hotp/";
        final String TYPE_TOTP = "totp/";
        final OtpAuth otpAuth = new OtpAuth();
        // 判断是否为 otpauth 协议
        if (!uri.startsWith(PROTOCOL)) {
            return null;
        }
        uri = uri.substring(PROTOCOL.length());
        // 判断 type
        if (uri.startsWith(TYPE_HOTP)) {
            otpAuth.type = Type.HOTP;
            uri = uri.substring(TYPE_HOTP.length());
        } else if (uri.startsWith(TYPE_TOTP)) {
            otpAuth.type = Type.TOTP;
            uri = uri.substring(TYPE_TOTP.length());
        } else {
            System.out.println("type not match.");
            return null;
        }
        // 拆分 label 和 参数
        String[] arr = uri.split("\\?");
        String label = arr[0];
        String qs = arr[1];
        otpAuth.label = label;
        // 拆分 accountName 和 issuer
        if (label.contains(":")) {
            arr = label.split(":");
            otpAuth.issuer = arr[0];
            otpAuth.accountName = arr[1];
            if (otpAuth.accountName.startsWith(" ")) {
                otpAuth.accountName = otpAuth.accountName.substring(1);
            }
        } else {
            otpAuth.accountName = label;
        }
        // 拆分 参数
        final String[] params = qs.split("&");
        for (String param : params) {
            arr = param.split("=");
            String key = arr[0];
            String value = arr[1];
            switch (key) {
                case "secret" -> {
                    otpAuth.secret = value;
                }
                case "issuer" -> {
                    if (otpAuth.issuer != null && !otpAuth.issuer.equals(value)) {
                        System.out.println("label-issuer and params-issuer not match.");
                        System.out.printf("unknown params key: %s.%n", key);
                        return null;
                    }
                    otpAuth.issuer = value;
                }
                case "algorithm" -> {
                    otpAuth.algorithm = Algorithm.valueOf(value);
                }
                case "digits" -> {
                    otpAuth.digits = Integer.valueOf(value);
                }
                case "counter" -> {
                    otpAuth.counter = Integer.valueOf(value);
                }
                case "period" -> {
                    otpAuth.period = Integer.valueOf(value);
                }
                default -> {
                    System.out.printf("unknown params key: %s.%n", key);
                    return null;
                }
            }
        }
        return otpAuth;
    }

    /**
     * 类型
     */
    private Type type;

    /**
     * 标签
     */
    private String label;

    /**
     * 发行者
     */
    private String issuer;

    /**
     * 账号名
     */
    private String accountName;

    /**
     * 密钥
     */
    private String secret;

    /**
     * 算法
     * 默认: SHA1
     */
    private Algorithm algorithm;

    /**
     * 密码长度
     * 一般为 6 或 8
     * 默认: 6
     */
    private Integer digits;

    /**
     * HOTP 初始计数值
     * 当 type 为 HOTP 时生效
     */
    private Integer counter;

    /**
     * TOTP 代码的有效期限
     * 当 type 为 TOTP 时生效
     * 默认: 30
     */
    private Integer period;

    private OtpAuth() {
    }

    public Type getType() {
        return type;
    }

    public String getLabel() {
        return label;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getAccountName() {
        return accountName;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public Integer getDigits() {
        return digits;
    }

    public Integer getCounter() {
        return counter;
    }

    public Integer getPeriod() {
        return period;
    }

    public String toUri() {
        StringBuilder builder = new StringBuilder();
        builder.append("otpauth://");
        switch (this.type) {
            case HOTP -> builder.append("hotp/");
            case TOTP -> builder.append("totp/");
        }
        builder.append(this.label);
        builder.append("?secret=");
        builder.append(this.secret);
        if (this.issuer != null) {
            builder.append("&issuer=");
            builder.append(this.issuer);
        }
        if (this.algorithm != null) {
            builder.append("&algorithm=");
            switch (this.algorithm) {
                case SHA1 -> builder.append("SHA1");
                case SHA256 -> builder.append("SHA256");
                case SHA512 -> builder.append("SHA512");
            }
        }
        if (this.digits != null) {
            builder.append("&digits=");
            builder.append(this.digits);
        }
        if (this.counter != null) {
            builder.append("&counter=");
            builder.append(this.counter);
        }
        if (this.period != null) {
            builder.append("&period=");
            builder.append(this.period);
        }
        return builder.toString();
    }


}
