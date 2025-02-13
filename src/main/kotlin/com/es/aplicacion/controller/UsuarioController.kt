package com.es.aplicacion.controller

import com.es.aplicacion.dto.LoginUsuarioDTO
import com.es.aplicacion.dto.UsuarioDTO
import com.es.aplicacion.dto.UsuarioRegisterDTO
import com.es.aplicacion.error.exception.UnauthorizedException
import com.es.aplicacion.model.Usuario
import com.es.aplicacion.service.TokenService
import com.es.aplicacion.service.UsuarioService
import jakarta.servlet.http.HttpServletRequest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/app")
class UsuarioController {

    @Autowired
    private lateinit var authenticationManager: AuthenticationManager
    @Autowired
    private lateinit var tokenService: TokenService
    @Autowired
    private lateinit var usuarioService: UsuarioService

    @PostMapping("/register")
    fun insert(
        httpRequest: HttpServletRequest,
        @RequestBody usuarioRegisterDTO: UsuarioRegisterDTO
    ) : ResponseEntity<UsuarioDTO>?{
        // UserRegisterDTO
//        val username: String,
//        val email: String,
//        val password: String,
//        val passwordRepeat: String,
//        val rol: String?

        // user register
//        val username: String,
//        val email: String,
//        val password: String,
//        val passwordRepeat: String,
//        val rol: String?
        // TODO: Implementar este metodo


        if (usuarioRegisterDTO.username.isBlank()) throw UnauthorizedException("Nombre de usuario no válido")
        if (usuarioRegisterDTO.password.isBlank()) throw UnauthorizedException("Contraseña no válido")
        if (usuarioRegisterDTO.direccion.calle.isBlank()) throw UnauthorizedException("Calle no valida")
        if (usuarioRegisterDTO.direccion.num.isBlank()) throw UnauthorizedException("Numero no valido")
        if (usuarioRegisterDTO.direccion.cp.isBlank()) throw UnauthorizedException("CP no valido")
        if (usuarioRegisterDTO.direccion.provincia !in listOf("Cadiz", "Almeria", "Jaen")) throw UnauthorizedException("Provincia no valida")


        if (usuarioRegisterDTO.password != usuarioRegisterDTO.passwordRepeat) throw UnauthorizedException("Ambas contasñeas deben ser iguales")



        usuarioService.insertUser(usuarioRegisterDTO)


        return ResponseEntity(null, HttpStatus.CREATED)

    }

    @PostMapping("/login")
    fun login(@RequestBody usuario: LoginUsuarioDTO) : ResponseEntity<Any>? {

        val authentication: Authentication
        try {
            authentication = authenticationManager.authenticate(UsernamePasswordAuthenticationToken(usuario.username, usuario.password))
        } catch (e: AuthenticationException) {
            throw UnauthorizedException("Credenciales incorrectas")
        }

        // SI PASAMOS LA AUTENTICACIÓN, SIGNIFICA QUE ESTAMOS BIEN AUTENTICADOS
        // PASAMOS A GENERAR EL TOKEN
        var token = tokenService.generarToken(authentication)

        return ResponseEntity(mapOf("token" to token), HttpStatus.CREATED)
    }

}