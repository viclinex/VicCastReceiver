const context = cast.framework.CastReceiverContext.getInstance();
const options = new cast.framework.CastReceiverOptions();
options.maxInactivity = 3600;
const playerManager = context.getPlayerManager();
const CHANNEL = "urn:x-cast:com.google.cast.receiver";

console.log("context= " + context + " options= " + options + " playerManager= " + playerManager);

playerManager.setMessageInterceptor(
    cast.framework.messages.MessageType.LOAD,
    request => {
      // Resolve entity to content id
      if (request.media.entity && !request.media.contentId) {
        return getMediaByEntity(request.media.entity).then(
            media => {
              request.media.contentId = media.url;
              return request;
            });
      }
      return request;
    });

playerManager.addEventListener(
    cast.framework.events.category.REQUEST,
    event => logEvent(event.type));

context.start(options);
