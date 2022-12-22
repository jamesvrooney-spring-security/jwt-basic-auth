package com.jamesvrooney.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/greeting")
public class HelloController {

    @GetMapping
    public String hello() {
        final var greeting = "Hello James";

        return greeting;
    }
}
