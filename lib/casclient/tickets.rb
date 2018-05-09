module CASClient
  # Represents a CAS service ticket.
  class ServiceTicket
    attr_reader :ticket, :service, :renew
    attr_accessor :response, :reused
    
    def initialize(ticket, service, renew = false)
      @ticket = ticket
      @service = service
      @renew = renew
    end
    
    def is_valid?
      return true if @reused
      response.is_success?
    end
    
    def has_been_validated?
      return true if @reused
      not response.nil?
    end

    def as_json(options=nil)
      {
        :ticket  => @ticket,
        :service => @service,
        :renew   => @renew
      }
    end
  end
  
  # Represents a CAS proxy ticket.
  class ProxyTicket < ServiceTicket
  end
  
  class ProxyGrantingTicket
    attr_reader :ticket, :iou
    
    def initialize(ticket, iou)
      @ticket = ticket
      @iou = iou
    end
    
    def to_s
      ticket
    end
  end
end