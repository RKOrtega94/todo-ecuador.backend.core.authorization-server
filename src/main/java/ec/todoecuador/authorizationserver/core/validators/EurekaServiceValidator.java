package ec.todoecuador.authorizationserver.core.validators;

import ec.todoecuador.authorizationserver.core.properties.AppProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class EurekaServiceValidator {
    private final AppProperties props;
    private final DiscoveryClient discoveryClient;

    public boolean isCallerAllowed(String callerIp) {
        return props.getInternal().getAllowedServices().stream().anyMatch(serviceId -> isIpRegistered(serviceId, callerIp));
    }

    private boolean isIpRegistered(String service, String caller) {
        try {
            List<ServiceInstance> instances = discoveryClient.getInstances(service);
            if (instances.isEmpty()) return false;
            return instances.stream().map(ServiceInstance::getHost).anyMatch(host -> host.equals(caller));
        } catch (Exception e) {
            log.error("Error validating Eureka service {}: {}", service, e.getMessage());
            return false;
        }
    }
}