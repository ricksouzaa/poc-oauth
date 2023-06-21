package poc.oauth.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {

  @GetMapping
  String test(@AuthenticationPrincipal Object principal) {
    System.out.println(principal);
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    System.out.println(authentication);
    return "OK";
  }
}
