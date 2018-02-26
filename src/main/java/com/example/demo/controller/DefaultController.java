package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DefaultController {

    @GetMapping("/")
    public String login1() {
        return "/login";
    }

    @GetMapping("/login")
    public String login() {
        return "/login";
    }
    
    @GetMapping("/home")
    public String home() {
        return "/home";
    }
    
    @GetMapping("/admin")
    public String admin() {
        return "/admin";
    }

    @GetMapping("/403")
    public String error403() {
        return "/error/403";
    }

}
