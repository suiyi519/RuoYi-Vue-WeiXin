package com.ruoyi.web.controller.system;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.config.WxAppConfig;
import com.ruoyi.common.core.domain.model.WxLoginBody;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.common.utils.sign.Base64;
import com.ruoyi.framework.config.ApplicationConfig;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysMenu;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginBody;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.framework.web.service.SysLoginService;
import com.ruoyi.framework.web.service.SysPermissionService;
import com.ruoyi.system.service.ISysMenuService;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 登录验证
 * 
 * @author ruoyi
 */
@Api("登陆验证接口")
@RestController
public class SysLoginController
{
    @Autowired
    private SysLoginService loginService;

    @Autowired
    private ISysMenuService menuService;

    @Autowired
    private SysPermissionService permissionService;

    /**
     * 登录方法
     * 
     * @param loginBody 登录信息
     * @return 结果
     */
    @PostMapping("/login")
    public AjaxResult login(@RequestBody LoginBody loginBody)
    {
        AjaxResult ajax = AjaxResult.success();
        // 生成令牌
        String token = loginService.login(loginBody.getUsername(), loginBody.getPassword(), loginBody.getCode(),
                loginBody.getUuid());
        ajax.put(Constants.TOKEN, token);
        return ajax;
    }

    /**
     * 获取用户信息
     * 
     * @return 用户信息
     */
    @GetMapping("getInfo")
    public AjaxResult getInfo()
    {
        SysUser user = SecurityUtils.getLoginUser().getUser();
        // 角色集合
        Set<String> roles = permissionService.getRolePermission(user);
        // 权限集合
        Set<String> permissions = permissionService.getMenuPermission(user);
        AjaxResult ajax = AjaxResult.success();
        ajax.put("user", user);
        ajax.put("roles", roles);
        ajax.put("permissions", permissions);
        return ajax;
    }

    /**
     * 获取路由信息
     * 
     * @return 路由信息
     */
    @GetMapping("getRouters")
    public AjaxResult getRouters()
    {
        Long userId = SecurityUtils.getUserId();
        List<SysMenu> menus = menuService.selectMenuTreeByUserId(userId);
        return AjaxResult.success(menuService.buildMenus(menus));
    }


    @Autowired
    private WxAppConfig wxAppConfig;

    @Autowired
    private ApplicationConfig applicationConfig;

    /**
     * 微信登陆接口
     * @param wxLoginBody
     * @return
     */
    @ApiOperation("微信登陆接口")
    @PostMapping("/wxLogin")
    public AjaxResult wxLogin(@RequestBody WxLoginBody wxLoginBody) {
        String code = wxLoginBody.getCode();
        //秘钥
        String encryptedIv = wxLoginBody.getEncryptedIv();
        //加密数据
        String encryptedData = wxLoginBody.getEncryptedData();
        //向微信服务器发送请求获取用户信息
        String url = "https://api.weixin.qq.com/sns/jscode2session?appid=" + wxAppConfig.getAppId() + "&secret=" + wxAppConfig.getAppSecret() + "&js_code=" + code + "&grant_type=authorization_code";

        String res = applicationConfig.RestTemplate().getForObject(url, String.class);
        JSONObject jsonObject = JSONObject.parseObject(res);

        //获取session_key和openid
        String sessionKey = jsonObject.getString("session_key");
        String openid = jsonObject.getString("openid");

        //解密
        String decryptResult = "";
        try {
            //如果没有绑定微信开放平台，解析结果是没有unionid的。
            decryptResult = decrypt(sessionKey, encryptedIv, encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return AjaxResult.error("微信登录失败！");
        }

        if (StringUtils.hasText(decryptResult)) {
            //如果解析成功,获取token
            String token = loginService.wxLogin(decryptResult);
            AjaxResult ajax = AjaxResult.success();
            ajax.put(Constants.TOKEN, token);
            return ajax;
        } else {
            return AjaxResult.error("微信登录失败！");
        }
    }

    /**
     * AES解密
     */
    private String decrypt(String sessionKey,String encryptedIv,String encryptedData) throws Exception{
        // 转化为字节数组
        byte[] key = Base64.decode(sessionKey);
        byte[] iv = Base64.decode(encryptedIv);
        byte[] encData = Base64.decode(encryptedData);
        // 如果密钥不足16位，那么就补足
        int base =16;
        if (key.length % base !=0) {
            int groups = key.length / base +(key.length % base != 0 ? 1 : 0);
            byte[] temp = new byte[groups * base];
            Arrays.fill(temp,(byte) 0);
            System.arraycopy(key,0,temp,0,key.length);
            key = temp;
        }
        // 如果初始向量不足16位，也补足
        if (iv.length % base !=0) {
            int groups = iv.length / base +(iv.length % base != 0 ? 1 : 0);
            byte[] temp = new byte[groups * base];
            Arrays.fill(temp,(byte) 0);
            System.arraycopy(iv,0,temp,0,iv.length);
            iv = temp;
        }

        AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
        String resultStr = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(key,"AES");
            cipher.init(Cipher.DECRYPT_MODE,keySpec,ivSpec);
            resultStr = new String(cipher.doFinal(encData),"UTF-8");
        } catch (Exception e){
            //            logger.info("解析错误");
            e.printStackTrace();
        }

        // 解析加密后的字符串
        return resultStr;
    }
}
