package org.kapit.c2.mobile.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Shapes
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// Palette shared with the website's dark sign-in and navigation surfaces (web/src/auth.css).
internal val OliveAccent = Color(0xFFD5EE8E)
internal val WarmAccent = Color(0xFFE6C36F)
internal val PositiveAccent = Color(0xFF9DCB7A)

/** One radius scale for every surface: chips < controls < cards < dialogs. */
internal object KapitShape {
    val chip = RoundedCornerShape(6.dp)
    val control = RoundedCornerShape(10.dp)
    val card = RoundedCornerShape(12.dp)
    val dialog = RoundedCornerShape(16.dp)
}

private val KapitTypography = Typography().let { base ->
    base.copy(
        headlineMedium = base.headlineMedium.copy(fontWeight = FontWeight.SemiBold, letterSpacing = (-0.4).sp),
        headlineSmall = base.headlineSmall.copy(fontWeight = FontWeight.SemiBold, letterSpacing = (-0.2).sp),
        titleMedium = base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelMedium = base.labelMedium.copy(letterSpacing = 0.3.sp),
        bodyMedium = base.bodyMedium.copy(lineHeight = 21.sp),
        bodySmall = base.bodySmall.copy(lineHeight = 18.sp),
    )
}

@Composable
fun KapitMobileTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = OliveAccent,
            onPrimary = Color(0xFF1B231B),
            primaryContainer = Color(0xFF2C3A23),
            onPrimaryContainer = Color(0xFFE6F5C8),
            secondary = WarmAccent,
            onSecondary = Color(0xFF35230A),
            background = Color(0xFF121612),
            onBackground = Color(0xFFEEEEE5),
            surface = Color(0xFF181F17),
            onSurface = Color(0xFFEEEEE5),
            surfaceVariant = Color(0xFF232C20),
            onSurfaceVariant = Color(0xFFAEB8A3),
            surfaceContainer = Color(0xFF1C2419),
            surfaceContainerHigh = Color(0xFF222B1F),
            outline = Color(0xFF7A866E),
            outlineVariant = Color(0xFF2F3A2B),
            error = Color(0xFFF2A598),
            onError = Color(0xFF5C1A12),
            errorContainer = Color(0xFF3F1F1A),
            onErrorContainer = Color(0xFFFFDAD3),
        ),
        shapes = Shapes(extraSmall = KapitShape.chip, small = KapitShape.chip, medium = KapitShape.control,
            large = KapitShape.card, extraLarge = KapitShape.dialog),
        typography = KapitTypography,
        content = content,
    )
}

@Composable
internal fun BrandHeader(compact: Boolean = false) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Surface(shape = KapitShape.control, color = MaterialTheme.colorScheme.primaryContainer,
            border = BorderStroke(1.dp, OliveAccent.copy(alpha = .35f))) {
            Text("K", Modifier.padding(horizontal = if (compact) 11.dp else 14.dp, vertical = if (compact) 6.dp else 10.dp),
                style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Black,
                color = MaterialTheme.colorScheme.primary)
        }
        Spacer(Modifier.width(12.dp))
        Column {
            Text("KAPIT", fontWeight = FontWeight.Black, letterSpacing = 3.sp,
                style = if (compact) MaterialTheme.typography.titleLarge else MaterialTheme.typography.headlineMedium)
            Text("MAINTENANCE WORKSPACE", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
        }
    }
}

@Composable
internal fun PageTitle(eyebrow: String, title: String, description: String? = null) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(eyebrow.uppercase(), style = MaterialTheme.typography.labelMedium,
            letterSpacing = 1.5.sp, color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Monospace)
        Text(title, style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() })
        if (description != null) Text(description, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
internal fun SectionHeading(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { heading() })
}

@Composable
internal fun ContentCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Surface(modifier.fillMaxWidth(), shape = KapitShape.card,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
    }
}

@Composable
internal fun PrimaryAction(label: String, enabled: Boolean = true, icon: KapitIcon? = null, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
        shape = KapitShape.control, contentPadding = ButtonDefaults.ContentPadding) {
        if (icon != null) { KapitIconView(icon, size = 20.dp); Spacer(Modifier.width(10.dp)) }
        Text(label, Modifier.padding(vertical = 6.dp), fontWeight = FontWeight.SemiBold)
    }
}

@Composable
internal fun SecondaryAction(label: String, enabled: Boolean = true, icon: KapitIcon? = null, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().heightInTouchTarget(),
        shape = KapitShape.control,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = if (enabled) .7f else .3f))) {
        if (icon != null) { KapitIconView(icon, size = 18.dp); Spacer(Modifier.width(8.dp)) }
        Text(label, Modifier.padding(vertical = 6.dp), fontWeight = FontWeight.Medium)
    }
}

internal fun Modifier.heightInTouchTarget(): Modifier = this.then(Modifier.heightIn(min = 48.dp))

@Composable
internal fun StatusPill(text: String, warning: Boolean = false, positive: Boolean = false) {
    val tint = when { warning -> WarmAccent; positive -> PositiveAccent; else -> MaterialTheme.colorScheme.primary }
    Surface(shape = KapitShape.chip, color = tint.copy(alpha = .12f), border = BorderStroke(1.dp, tint.copy(alpha = .28f))) {
        Row(Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(7.dp)) {
            Box(Modifier.size(6.dp).background(tint, CircleShape))
            Text(text, style = MaterialTheme.typography.labelMedium, color = tint)
        }
    }
}

@Composable
internal fun NoticeCard(notice: MobileNotice, dismiss: (() -> Unit)? = null) {
    val accent = if (notice.isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    Surface(shape = KapitShape.card, modifier = Modifier.fillMaxWidth().semantics {
        liveRegion = if (notice.isError) LiveRegionMode.Assertive else LiveRegionMode.Polite
    }, color = if (notice.isError) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.primaryContainer,
        border = BorderStroke(1.dp, accent.copy(alpha = .35f))) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            KapitIconView(if (notice.isError) KapitIcon.ALERT else KapitIcon.SHIELD, size = 20.dp, tint = accent)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(notice.title, fontWeight = FontWeight.SemiBold)
                Text(notice.message, style = MaterialTheme.typography.bodyMedium)
                if (dismiss != null) TextButton(onClick = dismiss, modifier = Modifier.heightInTouchTarget()) { Text("Dismiss message") }
            }
        }
    }
}

@Composable
internal fun QuietText(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
internal fun Fact(label: String, value: String, monospace: Boolean = false) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = if (monospace) FontFamily.Monospace else null)
    }
}

@Composable
internal fun EmptyState(title: String, description: String, action: (@Composable () -> Unit)? = null) {
    ContentCard {
        SectionHeading(title)
        Text(description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        action?.invoke()
    }
}

/** A count with its label, for at-a-glance figures instead of label/value lists. */
@Composable
internal fun StatTile(label: String, value: String, modifier: Modifier = Modifier) {
    Surface(modifier, shape = KapitShape.control, color = MaterialTheme.colorScheme.surfaceVariant) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(value, style = MaterialTheme.typography.headlineSmall)
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

internal enum class StageTone { DONE, PENDING, ATTENTION }

/**
 * One stage of a report's progress. The tone only restates the stage's own reported value;
 * it never infers a later stage. Meaning is carried by the text, colour is supplementary.
 */
@Composable
internal fun StageRow(label: String, value: String, tone: StageTone) {
    val tint = when (tone) {
        StageTone.DONE -> PositiveAccent
        StageTone.ATTENTION -> WarmAccent
        StageTone.PENDING -> MaterialTheme.colorScheme.outline
    }
    Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(28.dp).background(tint.copy(alpha = .14f), CircleShape).border(1.dp, tint.copy(alpha = .5f), CircleShape),
            contentAlignment = Alignment.Center) {
            when (tone) {
                StageTone.DONE -> KapitIconView(KapitIcon.CHECK, size = 16.dp, tint = tint)
                StageTone.ATTENTION -> KapitIconView(KapitIcon.ALERT, size = 15.dp, tint = tint)
                StageTone.PENDING -> Box(Modifier.size(7.dp).background(tint, CircleShape))
            }
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
        }
    }
}

/** One numbered stage of a sequence, matching the website's process steps. */
@Composable
internal fun StepRow(number: Int, title: String, description: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
        Box(Modifier.size(28.dp).border(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = .45f), CircleShape),
            contentAlignment = Alignment.Center) {
            Text(number.toString(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary,
                fontFamily = FontFamily.Monospace)
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
