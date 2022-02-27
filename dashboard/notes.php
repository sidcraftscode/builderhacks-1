<?php
$note_name = 'note.txt';
$uniqueNotePerIP = true;

if($uniqueNotePerIP){

    // Use the user's IP as the name of the note.
    // This is useful when you have many people
    // using the app simultaneously.

    if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
        $note_name = 'notes/'.md5($_SERVER['HTTP_X_FORWARDED_FOR']).'.txt';
    }
    else{
        $note_name = 'notes/'.md5($_SERVER['REMOTE_ADDR']).'.txt';
    }
}

if(isset($_SERVER['HTTP_X_REQUESTED_WITH'])){
    // This is an AJAX request

    if(isset($_POST['note'])){
        // Write the file to disk
        file_put_contents($note_name, $_POST['note']);
        echo '{"saved":1}';
    }

    exit;
}

$note_content = '';

if( file_exists($note_name) ){
    $note_content = htmlspecialchars( file_get_contents($note_name) );
}
 ?>

<script   src="https://code.jquery.com/jquery-3.1.1.min.js"   integrity="sha256-hVVnYaiADRTO2PzUGmuLJr8BLUSjGIZsDYGmIJLv2b8="   crossorigin="anonymous"></script>
<script>
$(function(){

    var note = $('#note');

    var saveTimer,
        lineHeight = parseInt(note.css('line-height')),
        minHeight = parseInt(note.css('min-height')),
        lastHeight = minHeight,
        newHeight = 0,
        newLines = 0;

    var countLinesRegex = new RegExp('\n','g');

    // The input event is triggered on key press-es,
    // cut/paste and even on undo/redo.

    note.on('input',function(e){

        // Clearing the timeout prevents
        // saving on every key press
        clearTimeout(saveTimer);
        saveTimer = setTimeout(ajaxSaveNote, 2000);

        // Count the number of new lines
        newLines = note.val().match(countLinesRegex);

        if(!newLines){
            newLines = [];
        }

        // Increase the height of the note (if needed)
        newHeight = Math.max((newLines.length + 1)*lineHeight, minHeight);

        // This will increase/decrease the height only once per change
        if(newHeight != lastHeight){
            note.height(newHeight);
            lastHeight = newHeight;
        }
    }).trigger('input');    // This line will resize the note on page load

    function ajaxSaveNote(){

        // Trigger an AJAX POST request to save the note
        $.post('index.php', { 'note' : note.val() });
    }

});
</script>
<div id="pad">
    <h2>Note</h2>
    <textarea id="note"><?php echo $note_content ?></textarea>
</div>
