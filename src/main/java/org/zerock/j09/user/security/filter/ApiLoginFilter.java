package org.zerock.j09.user.security.filter;

import com.google.gson.Gson;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.j09.user.dto.MemberDTO;
import org.zerock.j09.user.security.util.JWTUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Log4j2
public class ApiLoginFilter extends AbstractAuthenticationProcessingFilter {
                                        // 로그인 URL
    public ApiLoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(defaultFilterProcessesUrl, authenticationManager);
    }

    @Override                                                                                               // 로그인 실패 시 인증예외 발생
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // 로그인 시도 시 여기로 넘어옴
        log.info("===========================================");
        log.info("===============attemp login================");
        log.info("===========================================");

        String email = request.getParameter("email");
        String pw = request.getParameter("pw");

        log.info("email: "+ email + " pw: " + pw);

        //인증매니저
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(email,pw);

        Authentication authResult = this.getAuthenticationManager().authenticate(authenticationToken);
        //인가 매니저에게 인가를 던져준다. 요렇게 하면 인가정보가 나온다       인증작업 실행

        log.info(authResult);


        return authResult;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("success login after.................");

        Object principal = authResult.getPrincipal();

        log.info(principal);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> map = new HashMap<>();

        String email = ((MemberDTO)principal).getUsername();

        try {
            String jwt = new JWTUtil().generateToken(email);

            map.put("TOKEN",jwt);

            Gson gson = new Gson();
            String str = gson.toJson(map);

            response.getWriter().println(str);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}








