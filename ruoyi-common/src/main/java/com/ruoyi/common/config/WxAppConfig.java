package com.ruoyi.common.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Component
@Configuration
public class WxAppConfig {

    @Value("${wx-app.appId}")
    private String appId;

    @Value("${wx-app.appSecret}")
    private String AppSecret;

    public String getAppId() {
        return appId;
    }

    public String getAppSecret() {
        return AppSecret;
    }
}
