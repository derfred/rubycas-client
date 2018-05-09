module CASClient
  module Frameworks
    module Rails
      class RequestHandler

        attr_accessor :use_gatewaying

        def self.handle_request(controller, use_gatewaying=false)
          new(controller, use_gatewaying=false).handle_request
        end

        def initialize(controller, use_gatewaying=false)
          @controller = controller
          @use_gatewaying = use_gatewaying
        end

        def handle_request
          return :single_sign_out if single_sign_out?(@controller)

          st, new_session = determine_request_context(@controller)
          if st
            handle_ticket(@controller, st, new_session)
          else
            handle_no_ticket(@controller)
          end
        end

        def config
          CASClient::Frameworks::Rails::Filter.config
        end

        def client
          CASClient::Frameworks::Rails::Filter.client
        end

        def log
          CASClient::Frameworks::Rails::Filter.log
        end

        private
          # high level request handlers
          def handle_ticket(controller, st, new_session)
            st = client.validate_service_ticket(st) unless st.has_been_validated?
            vr = st.response

            if st.is_valid?
              setup_new_session(controller, st, vr) if new_session

              # Store the ticket in the session to avoid re-validating the same service
              # ticket with the CAS server.
              controller.session[:cas_last_valid_ticket] = st

              handle_pgt_request(vr) if vr and vr.pgt_iou

              return :allow
            else
              log.warn("Ticket #{st.ticket.inspect} failed validation -- #{vr.failure_code}: #{vr.failure_message}")
              return :validation_failed
            end
          end

          def handle_no_ticket(controller)
            if returning_from_gateway?(controller)
              log.info "Returning from CAS gateway without authentication."

              if use_gatewaying?
                log.info "This CAS client is configured to use gatewaying, so we will permit the user to continue without authentication."
                return :allow
              else
                log.warn "The CAS client is NOT configured to allow gatewaying, yet this request was gatewayed. Something is not right!"
              end
            end

            return :to_login
          end

          def handle_pgt_request(controller)
            unless controller.session[:cas_pgt] && controller.session[:cas_pgt].ticket && controller.session[:cas_pgt].iou == vr.pgt_iou
              log.info("Receipt has a proxy-granting ticket IOU. Attempting to retrieve the proxy-granting ticket...")
              pgt = client.retrieve_proxy_granting_ticket(vr.pgt_iou)

              if pgt
                log.debug("Got PGT #{pgt.ticket.inspect} for PGT IOU #{pgt.iou.inspect}. This will be stored in the session.")
                controller.session[:cas_pgt] = pgt
                # For backwards compatibility with RubyCAS-Client 1.x configurations...
                controller.session[:casfilterpgt] = pgt
              else
                log.error("Failed to retrieve a PGT for PGT IOU #{vr.pgt_iou}!")
              end
            else
              log.info("PGT is present in session and PGT IOU #{vr.pgt_iou} matches the saved PGT IOU.  Not retrieving new PGT.")
            end
          end


          # single sign out functionality
          def single_sign_out?(controller)
            # Avoid calling raw_post (which may consume the post body) if
            # this seems to be a file upload
            if content_type = controller.request.headers["CONTENT_TYPE"] &&
                content_type =~ %r{^multipart/}
              return false
            end

            if controller.request.post? &&
                controller.params['logoutRequest'] &&
                controller.params['logoutRequest'] =~
                  %r{^<samlp:LogoutRequest.*?<samlp:SessionIndex>(.*)</samlp:SessionIndex>}m
              # TODO: Maybe check that the request came from the registered CAS server? Although this might be
              #       pointless since it's easily spoofable...
              si = $~[1]

              unless config[:enable_single_sign_out]
                log.warn "Ignoring single-sign-out request for CAS session #{si.inspect} because ssout functionality is not enabled (see the :enable_single_sign_out config option)."
                return false
              end

              log.debug "Intercepted single-sign-out request for CAS session #{si.inspect}."

              required_sess_store = session_store
              current_sess_store  = ActionController::Base.session_options[:database_manager]

              if current_sess_store == required_sess_store
                session_id = read_service_session_lookup(si)

                if session_id
                  session = session_store::Session.find_by_session_id(session_id)
                  if session
                    session.destroy
                    log.debug("Destroyed #{session.inspect} for session #{session_id.inspect} corresponding to service ticket #{si.inspect}.")
                  else
                    log.debug("Data for session #{session_id.inspect} was not found. It may have already been cleared by a local CAS logout request.")
                  end

                  log.info("Single-sign-out for session #{session_id.inspect} completed successfuly.")
                else
                  log.warn("Couldn't destroy session with SessionIndex #{si} because no corresponding session id could be looked up.")
                end
              else
                log.error "Cannot process logout request because this Rails application's session store is "+
                  " #{current_sess_store.name.inspect}. Single Sign-Out only works with the "+
                  " #{required_sess_store.name.inspect} session store."
              end

              # Return true to indicate that a single-sign-out request was detected
              # and that further processing of the request is unnecessary.
              return true
            end

            # This is not a single-sign-out request.
            return false
          end

          def session_store
            if CGI.const_defined?("Session")
              CGI::Session::ActiveRecordStore
            else
              ActiveRecord::SessionStore
            end
          end

          # Creates a file in tmp/sessions linking a SessionTicket
          # with the local Rails session id. The file is named
          # cas_sess.<session ticket> and its text contents is the corresponding
          # Rails session id.
          # Returns the filename of the lookup file created.
          def store_service_session_lookup(st, sid)
            st = st.ticket if st.kind_of? ServiceTicket
            f = File.new(filename_of_service_session_lookup(st), 'w')
            f.write(sid)
            f.close
            return f.path
          end

          # Returns the local Rails session ID corresponding to the given
          # ServiceTicket. This is done by reading the contents of the
          # cas_sess.<session ticket> file created in a prior call to 
          # #store_service_session_lookup.
          def read_service_session_lookup(st)
            st = st.ticket if st.kind_of? ServiceTicket
            ssl_filename = filename_of_service_session_lookup(st)
            return File.exists?(ssl_filename) && IO.read(ssl_filename)
          end

          # Removes a stored relationship between a ServiceTicket and a local
          # Rails session id. This should be called when the session is being
          # closed.
          #
          # See #store_service_session_lookup.
          def delete_service_session_lookup(st)
            st = st.ticket if st.kind_of? ServiceTicket
            ssl_filename = filename_of_service_session_lookup(st)
            File.delete(ssl_filename) if File.exists?(ssl_filename)
          end

          # Returns the path and filename of the service session lookup file.
          def filename_of_service_session_lookup(st)
            st = st.ticket if st.kind_of? ServiceTicket
            return "#{RAILS_ROOT}/tmp/sessions/cas_sess.#{st}"
          end

          def determine_request_context(controller)
            last_st = deserialize controller.session[:cas_last_valid_ticket]
            st = read_ticket(controller)

            if last_st &&
                !authenticate_on_every_request?(controller) &&
                controller.session[client.username_session_key]
              # Re-use the previous ticket if the user already has a local CAS session (i.e. if they were already
              # previously authenticated for this service). This is to prevent redirection to the CAS server on every
              # request.
              # This behaviour can be disabled (so that every request is routed through the CAS server) by setting
              # the :authenticate_on_every_request config option to false.
              log.debug "Existing local CAS session detected for #{controller.session[client.username_session_key].inspect}. "+
                            "Previous ticket #{last_st.ticket.inspect} will be re-used."
              last_st.reused = true
              return [last_st, false]
            elsif last_st &&
                authenticate_on_every_request?(controller) &&
                controller.session[client.username_session_key]

              client.validate_service_ticket(last_st)

              if last_st.is_valid?
                return [last_st, false]
              else
                controller.session[client.username_session_key] = nil
                controller.session[:cas_last_valid_ticket]      = nil
                return [nil, false]
              end
            else
              return [st, true]
            end
          end

          def deserialize(ticket_or_hash)
            if ticket_or_hash.is_a?(Hash)
              ServiceTicket.new ticket_or_hash['ticket'], ticket_or_hash['service'], ticket_or_hash['renew']
            else
              ticket_or_hash
            end
          end

          def read_ticket(controller)
            ticket = controller.params[:ticket]

            return nil unless ticket

            log.debug("Request contains ticket #{ticket.inspect}.")

            if ticket =~ /^PT-/
              ProxyTicket.new(ticket, read_service_url(controller), controller.params[:renew])
            else
              ServiceTicket.new(ticket, read_service_url(controller), controller.params[:renew])
            end
          end

          def read_service_url(controller)
            CASClient::Frameworks::Rails::Filter.read_service_url(controller)
          end

          def setup_new_session(controller, st, vr)
            controller.send(:reset_session)
            log.info("Ticket #{st.ticket.inspect} for service #{st.service.inspect} belonging to user #{vr.user.inspect} is VALID.")
            controller.session[client.username_session_key] = vr.user.dup
            controller.session[client.extra_attributes_session_key] = HashWithIndifferentAccess.new(vr.extra_attributes.dup)

            if vr.extra_attributes
              log.debug("Extra user attributes provided along with ticket #{st.ticket.inspect}: #{vr.extra_attributes.inspect}.")
            end

            # RubyCAS-Client 1.x used :casfilteruser as it's username session key,
            # so we need to set this here to ensure compatibility with configurations
            # built around the old client.
            controller.session[:casfilteruser] = vr.user

            if config[:enable_single_sign_out]
              store_service_session_lookup(st, controller.session.session_id)
              log.debug("Wrote service session lookup file to #{f.inspect} with session id #{controller.session.session_id.inspect}.")
            end
          end


          # gatewaying support
          def returning_from_gateway?(controller)
            controller.session[:cas_sent_to_gateway]
          end

          def use_gatewaying?
            @use_gatewaying
          end

          def authenticate_on_every_request?(controller)
            if config[:authenticate_on_every_request].respond_to?(:call)
              config[:authenticate_on_every_request].call(controller)
            else
              config[:authenticate_on_every_request]
            end
          end

      end
    end
  end
end
