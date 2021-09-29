package mx.com.lickodev.udemy.control.users.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import mx.com.lickodev.udemy.control.commons.entity.projections.IUserDTO;
import mx.com.lickodev.udemy.control.commons.entity.users.User;

/**
 * @author saul_
 * 
 * 
 *         https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#projections.interfaces
 *         https://www.baeldung.com/spring-data-rest-projections-excerpts
 *
 */
@RepositoryRestResource(path = "users", excerptProjection = IUserDTO.class)
public interface UsersRepository extends JpaRepository<User, Long> {

	public IUserDTO findByUserName(@Param("userName") String userName);

}
