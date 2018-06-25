module CASClient
  module Frameworks
    module Rails
      class Filter

        cattr_accessor :config, :log, :client

        # These are initialized when you call configure.
        @@config = nil
        @@client = nil
        @@log = nil

        def self.use_gatewaying?
          @@config[:use_gatewaying]
        end

        def self.filter(controller)
          raise "Cannot use the CASClient filter because it has not yet been configured." if config.nil?

          case RequestHandler.determine_response(condition, use_gatewaying?)
          when :single_sign_out
            controller.send(:render, :text => "CAS Single-Sign-Out request intercepted.")
            return false
          when :allow, :new_session
            return true
          when :to_login
            redirect_to_cas_for_authentication(controller)
            return false
          when :validation_failed
            redirect_to_cas_for_authentication(controller)
            return false
          end
        end

        def self.configure(config)
          @@config = config
          @@config[:logger] = ::Rails.logger unless @@config[:logger]
          @@client = CASClient::Client.new(config)
          @@log = client.log
        end

        # this guesses the service_url which is requesting the login
        def self.read_service_url(controller)
          if config[:service_url].is_a?(Proc)
              service_url = config[:service_url].call(controller)
              log.debug("Using explicitly set service url: #{service_url}")
              return service_url
            elsif config[:service_url]
              log.debug("Using explicitly set service url: #{config[:service_url]}")
              return config[:service_url]
            end

          params = controller.params.dup
          params.delete(:ticket)
          params.delete(:format) if params[:format].to_s == 'html'
::Rails.logger.info params.inspect

          service_url = controller.url_for(params.permit!)
          ::Rails.logger.info("Guessed service url: #{service_url.inspect}")
          return service_url
        end

        # Returns the login URL for the current controller. 
        # Useful when you want to provide a "Login" link in a GatewayFilter'ed
        # action. 
        def self.login_url(controller)
          service_url = read_service_url(controller)
          url = client.add_service_to_login_url(service_url)
          log.debug("Generated login url: #{url}")
          return url
        end

        # Clears the given controller's local Rails session, does some local 
        # CAS cleanup, and redirects to the CAS logout page. Additionally, the
        # <tt>request.referer</tt> value from the <tt>controller</tt> instance 
        # is passed to the CAS server as a 'destination' parameter. This 
        # allows RubyCAS server to provide a follow-up login page allowing
        # the user to log back in to the service they just logged out from 
        # using a different username and password. Other CAS server 
        # implemenations may use this 'destination' parameter in different 
        # ways. 
        # If given, the optional <tt>service</tt> URL overrides 
        # <tt>request.referer</tt>.
        def self.logout(controller, service = nil)
          referer = service || controller.request.referer
          st = controller.session[:cas_last_valid_ticket]
          controller.send(:reset_session)
          controller.send(:redirect_to, client.logout_url(referer))
        end

        def self.redirect_to_cas_for_authentication(controller)
          redirect_url = login_url(controller)

          if use_gatewaying?
            controller.session[:cas_sent_to_gateway] = true
            redirect_url << "&gateway=true"
          else
            controller.session[:cas_sent_to_gateway] = false
          end

          if controller.session[:previous_redirect_to_cas] &&
                controller.session[:previous_redirect_to_cas] > (Time.now - 1.second)
            log.warn("Previous redirect to the CAS server was less than a second ago. The client at #{controller.request.remote_ip.inspect} may be stuck in a redirection loop!")
            controller.session[:cas_validation_retry_count] ||= 0

            if controller.session[:cas_validation_retry_count] > 3
              log.error("Redirection loop intercepted. Client at #{controller.request.remote_ip.inspect} will be redirected back to login page and forced to renew authentication.")
              redirect_url += "&renew=1&redirection_loop_intercepted=1"
            end

            controller.session[:cas_validation_retry_count] += 1
          else
            controller.session[:cas_validation_retry_count] = 0
          end
          controller.session[:previous_redirect_to_cas] = Time.now

          log.debug("Redirecting to #{redirect_url.inspect}")
          controller.send(:redirect_to, redirect_url)
        end

      end

    
      class GatewayFilter < Filter
        def self.use_gatewaying?
          return true unless @@config[:use_gatewaying] == false
        end
      end
    end
  end
end
