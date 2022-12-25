/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/AnnotationType.java to edit this template
 */
package org.asterisk.crypto;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The presence of this annotation on any public field (including enum
 * constants) containing a cryptographic algorithm implies that that
 * implementation has been exhaustively tested
 * <p>
 * The presence of this annotation on a constructor also implies that
 * all the public methods accessible of that object are also tested exhaustively
 *
 * @author Sayantan Chakraborty
 */
@Target({ElementType.FIELD, ElementType.CONSTRUCTOR, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Tested {

}
