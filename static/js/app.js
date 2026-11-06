/**
 * Set the minimum selectable date to the user's local date.
 */

document.addEventListener("DOMContentLoaded", function () {

    // Prevent selecting past dates in empty date fields.
    document.querySelectorAll('input[type="date"]').forEach(function (field) {

        // Preserve existing values and minimum-date restrictions.
        if (!field.value && !field.min) {
            const today = new Date();

            // Calculate the date using the user's local timezone.
            const localDate = new Date(
                today.getTime() - today.getTimezoneOffset() * 60000
            ).toISOString().split("T")[0];

            field.min = localDate;
        }

    });

});