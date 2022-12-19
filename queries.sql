CREATE OR REPLACE PROCEDURE UpdateContentTsVectors(param_contentId bigint) AS $$
DECLARE
	var_caption text;
	var_displayName text;
BEGIN
	SELECT (caption,displayName) FROM Content INTO var_caption, var_displayName WHERE contentId = param_contentId;
	UPDATE Content SET displayName_tsvector = to_tsvector(var_displayName), caption_tsvector = to_tsvector(var_caption);
END; 
$$ LANGUAGE plpgsql;
